"""AgentShield: a security gateway that sits between A2A agents.

Every agent-to-agent call goes   caller -> gateway -> target agent,   and passes these checks:

    1. authenticate      caller id + key (agents never call each other directly)
    2. rate limit        stops runaway loops and floods
    3. trusted target    target is registered AND its Agent Card still matches the pinned
                         fingerprint (detects tampered / swapped agents)
    4. capability policy caller may use this skill on this target (least privilege)
    5. injection scan    every text in the request (and later the response)
    6. PII redaction     identifiers the target doesn't need are replaced
    7. human approval    high-risk actions (large payments) are held, not executed
    8. audit log         one record per call: who, what, decision, reasons, timings

Blocked calls get a JSON-RPC error; held calls get an A2A Task in TASK_STATE_INPUT_REQUIRED.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import tomllib
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import a2a, pii
from .a2a import A2AError
from .detector import Detector

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "config" / "policy.toml"
GATEWAY_TOKEN_HEADER = "X-AgentShield-Token"

# JSON-RPC error codes used by the gateway
E_UNAUTHENTICATED = -32001
E_RATE_LIMITED = -32002
E_UNTRUSTED_AGENT = -32003
E_FORBIDDEN_SKILL = -32005
E_INJECTION = -32010
E_RESPONSE_INJECTION = -32011
E_UPSTREAM = -32020


def card_fingerprint(card: dict) -> str:
    return hashlib.sha256(json.dumps(card, sort_keys=True).encode()).hexdigest()


def _strings(obj) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in _strings(v)]
    if isinstance(obj, list):
        return [s for v in obj for s in _strings(v)]
    return []


def _segments(texts: list[str]) -> list[str]:
    """Split long texts into lines/sentences so one bad sentence can't hide in a document."""
    segs = []
    for t in texts:
        for line in t.splitlines():
            for s in re.split(r"(?<=[.!?;])\s+", line):
                if len(s.strip()) >= 12:
                    segs.append(s.strip())
    return segs


@dataclass
class Policy:
    agents: dict            # agent_id -> {"url": ..., "pii_allowed": [...]}
    callers: dict           # caller_id -> {"allowed": ["agent:skill", ...]}
    human_approval_limit: float = 150_000
    rate_limit_per_minute: int = 30
    scan_requests: bool = True
    scan_responses: bool = True
    enforce_capabilities: bool = True
    redact_pii: bool = True

    @classmethod
    def load(cls, path: Path = DEFAULT_POLICY, **overrides) -> "Policy":
        cfg = tomllib.loads(Path(path).read_text(encoding="utf-8"))
        g = cfg.get("gateway", {})
        p = cls(agents=cfg["agents"], callers=cfg["callers"],
                human_approval_limit=g.get("human_approval_limit", 150_000),
                rate_limit_per_minute=g.get("rate_limit_per_minute", 30))
        for k, v in overrides.items():
            setattr(p, k, v)
        return p

    def allowed(self, caller: str, target: str, skill: str) -> bool:
        return f"{target}:{skill}" in self.callers.get(caller, {}).get("allowed", [])


def dev_key(agent_id: str) -> str:
    """Per-agent secret from AGENTSHIELD_KEY_<ID>; falls back to a dev key for local demos."""
    return os.getenv(f"AGENTSHIELD_KEY_{agent_id.upper()}", f"dev-key-{agent_id}")


def gateway_token() -> str:
    return os.getenv("AGENTSHIELD_GATEWAY_TOKEN", "dev-gateway-token")


@dataclass
class Gateway:
    policy: Policy
    detector: Detector
    transport: httpx.AsyncBaseTransport | None = None   # None = real HTTP
    audit_path: Path | None = None
    pinned: dict = field(default_factory=dict)            # agent_id -> fingerprint
    cards: dict = field(default_factory=dict)             # agent_id -> pinned card
    quarantined: dict = field(default_factory=dict)       # agent_id -> reason
    pending: dict = field(default_factory=dict)           # approval_id -> held request
    audit: list = field(default_factory=list)
    _calls: dict = field(default_factory=lambda: defaultdict(deque))

    # ------------------------------------------------------------------ trust
    def _http(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=self.transport, timeout=30,
                                 headers={GATEWAY_TOKEN_HEADER: gateway_token(),
                                          "A2A-Version": a2a.PROTOCOL_VERSION})

    async def _fetch_card(self, agent_id: str) -> dict:
        async with self._http() as c:
            r = await c.get(self.policy.agents[agent_id]["url"].rstrip("/") + a2a.CARD_PATH)
            r.raise_for_status()
            return r.json()

    async def pin_all(self) -> dict:
        """Trust-on-setup: record the fingerprint of every registered agent's card."""
        for agent_id in self.policy.agents:
            card = await self._fetch_card(agent_id)
            self.cards[agent_id], self.pinned[agent_id] = card, card_fingerprint(card)
        self.quarantined.clear()
        return dict(self.pinned)

    async def refresh_cards(self) -> dict:
        """Re-fetch every card; quarantine agents whose card changed since pinning."""
        for agent_id in self.policy.agents:
            try:
                card = await self._fetch_card(agent_id)
            except Exception as e:
                self.quarantined[agent_id] = f"card unreachable ({type(e).__name__})"
                continue
            if card_fingerprint(card) != self.pinned.get(agent_id):
                self.quarantined[agent_id] = "agent card changed since it was pinned"
        return dict(self.quarantined)

    async def register(self, url: str) -> dict:
        """Someone asks the gateway to trust a new agent. Never auto-trusted."""
        async with self._http() as c:
            r = await c.get(url.rstrip("/") + a2a.CARD_PATH)
            card = r.json()
        for agent_id, trusted in self.cards.items():
            if card.get("name") == trusted.get("name") and \
                    url.rstrip("/") != self.policy.agents[agent_id]["url"].rstrip("/"):
                decision = {"status": "rejected", "reason": f"impersonates trusted agent '{agent_id}'"}
                self._log("registry", "-", "register", "blocked", [decision["reason"]], {}, 0.0)
                return decision
        self._log("registry", "-", "register", "held", ["new agent needs admin review"], {}, 0.0)
        return {"status": "pending_review", "card_name": card.get("name")}

    # ------------------------------------------------------------------ main path
    def _log(self, caller, target, skill, decision, reasons, timings, total_ms, trace_id=None):
        rec = {"ts": round(time.time(), 3), "trace_id": trace_id or a2a.new_id()[:12],
               "caller": caller, "target": target, "skill": skill, "decision": decision,
               "reasons": reasons, "timings_ms": timings, "latency_ms": round(total_ms, 2)}
        self.audit.append(rec)
        if self.audit_path:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.audit_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
        return rec

    def _rate_ok(self, caller: str) -> bool:
        now, q = time.monotonic(), self._calls[caller]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= self.policy.rate_limit_per_minute:
            return False
        q.append(now)
        return True

    def _scan(self, obj) -> dict | None:
        segs = _segments(_strings(obj))
        if not segs:
            return None
        scores = self.detector.scores(segs)
        i = int(scores.argmax())
        if scores[i] >= self.detector.threshold:
            return {"score": round(float(scores[i]), 3), "text": segs[i][:120]}
        return None

    async def handle(self, caller: str, key: str, target: str, body: dict) -> dict:
        """Process one JSON-RPC SendMessage from `caller` to `target`. Returns a JSON-RPC payload."""
        t0, timings, reasons = time.perf_counter(), {}, []
        req_id = body.get("id")
        message = (body.get("params") or {}).get("message") or {}
        skill = (message.get("metadata") or {}).get("skillId", "?")

        def lap(name, start):
            timings[name] = round((time.perf_counter() - start) * 1000, 3)

        def block(code, reason, data=None):
            self._log(caller, target, skill, "blocked", [reason], timings,
                      (time.perf_counter() - t0) * 1000)
            return a2a.rpc_error(req_id, A2AError(code, f"Blocked by AgentShield: {reason}", data))

        s = time.perf_counter()
        if caller not in self.policy.callers or key != dev_key(caller):
            lap("auth", s)
            return block(E_UNAUTHENTICATED, "unknown caller or wrong key")
        lap("auth", s)
        if not self._rate_ok(caller):
            return block(E_RATE_LIMITED, "rate limit exceeded")

        s = time.perf_counter()
        if target not in self.policy.agents or target not in self.pinned:
            lap("trust", s)
            return block(E_UNTRUSTED_AGENT, f"'{target}' is not a registered, pinned agent")
        if target in self.quarantined:
            lap("trust", s)
            return block(E_UNTRUSTED_AGENT, f"'{target}' is quarantined: {self.quarantined[target]}")
        if skill not in a2a.card_skill_ids(self.cards[target]):
            lap("trust", s)
            return block(a2a.ERR_UNSUPPORTED_SKILL, f"'{target}' has no skill '{skill}'")
        lap("trust", s)

        s = time.perf_counter()
        if self.policy.enforce_capabilities and not self.policy.allowed(caller, target, skill):
            lap("capability", s)
            return block(E_FORBIDDEN_SKILL, f"'{caller}' may not call {target}:{skill}")
        lap("capability", s)

        if self.policy.scan_requests:
            s = time.perf_counter()
            hit = self._scan(message.get("parts", []))
            lap("injection_scan", s)
            if hit:
                return block(E_INJECTION, "prompt injection detected in request", hit)

        if self.policy.redact_pii:
            s = time.perf_counter()
            allowed = set(self.policy.agents[target].get("pii_allowed", []))
            message["parts"], found = pii.redact(message.get("parts", []), allowed)
            lap("pii", s)
            if found:
                reasons.append(f"redacted: {sorted(set(found))}")

        if skill == "approve_payment":
            amount = a2a.message_data(message).get("invoice", {}).get("amount") or 0
            if amount > self.policy.human_approval_limit:
                approval_id = a2a.new_id()[:10]
                self.pending[approval_id] = {"caller": caller, "target": target, "body": body}
                self._log(caller, target, skill, "held", reasons + [f"amount {amount:,.0f} above "
                          f"human-approval limit {self.policy.human_approval_limit:,.0f}"],
                          timings, (time.perf_counter() - t0) * 1000)
                return a2a.rpc_result(req_id, a2a.task_result(
                    a2a.TASK_INPUT_REQUIRED, "Held for human approval", {"approval_id": approval_id,
                                                                         "amount": amount}))

        return await self._forward(caller, target, skill, body, req_id, timings, reasons, t0)

    async def _forward(self, caller, target, skill, body, req_id, timings, reasons, t0):
        s = time.perf_counter()
        try:
            async with self._http() as c:
                r = await c.post(self.policy.agents[target]["url"].rstrip("/") + a2a.RPC_PATH, json=body)
                payload = r.json()
        except Exception as e:
            timings["upstream"] = round((time.perf_counter() - s) * 1000, 3)
            self._log(caller, target, skill, "error", [f"upstream: {type(e).__name__}"], timings,
                      (time.perf_counter() - t0) * 1000)
            return a2a.rpc_error(req_id, A2AError(E_UPSTREAM, "Target agent unreachable"))
        timings["upstream"] = round((time.perf_counter() - s) * 1000, 3)

        if "result" in payload:
            if self.policy.scan_responses:
                s = time.perf_counter()
                hit = self._scan(payload["result"])
                timings["response_scan"] = round((time.perf_counter() - s) * 1000, 3)
                if hit:
                    self._log(caller, target, skill, "blocked", ["prompt injection in response"],
                              timings, (time.perf_counter() - t0) * 1000)
                    return a2a.rpc_error(req_id, A2AError(
                        E_RESPONSE_INJECTION, "Blocked by AgentShield: prompt injection in response", hit))
            if self.policy.redact_pii:
                allowed = set(self.policy.agents.get(caller, {}).get("pii_allowed", ["bank"]))
                payload["result"], found = pii.redact(payload["result"], allowed)
                if found:
                    reasons.append(f"redacted in response: {sorted(set(found))}")
        self._log(caller, target, skill, "allowed", reasons, timings, (time.perf_counter() - t0) * 1000)
        return payload

    async def decide(self, approval_id: str, approve: bool, reviewer: str = "human") -> dict:
        held = self.pending.pop(approval_id, None)
        if held is None:
            return {"status": "unknown approval id"}
        if not approve:
            self._log(reviewer, held["target"], "approve_payment", "rejected_by_human", [], {}, 0.0)
            return {"status": "rejected"}
        t0 = time.perf_counter()
        return await self._forward(held["caller"], held["target"], "approve_payment", held["body"],
                                   held["body"].get("id"), {}, [f"approved by {reviewer}"], t0)


# --------------------------------------------------------------------------- HTTP app
def create_gateway_app(gw: Gateway, public_url: str = "http://gateway") -> FastAPI:
    app = FastAPI(title="AgentShield gateway")
    app.state.gw = gw

    @app.get("/agents")
    async def directory():
        """Discovery: only trusted, non-quarantined agents, with URLs pointing at the gateway."""
        return [_proxied(agent_id) for agent_id in gw.cards if agent_id not in gw.quarantined]

    def _proxied(agent_id: str) -> dict:
        card = json.loads(json.dumps(gw.cards[agent_id]))
        card["supportedInterfaces"][0]["url"] = f"{public_url}/agents/{agent_id}/a2a"
        return card

    @app.get("/agents/{agent_id}" + a2a.CARD_PATH)
    async def agent_card(agent_id: str):
        if agent_id not in gw.cards or agent_id in gw.quarantined:
            return JSONResponse({"error": "unknown or quarantined agent"}, status_code=404)
        return _proxied(agent_id)

    @app.post("/agents/{agent_id}/a2a")
    async def rpc(agent_id: str, request: Request):
        body = await request.json()
        return JSONResponse(await gw.handle(request.headers.get("x-agent-id", ""),
                                            request.headers.get("x-agent-key", ""), agent_id, body))

    @app.post("/registry/register")
    async def register(payload: dict):
        return await gw.register(payload["url"])

    @app.get("/approvals")
    async def approvals():
        return {k: {"caller": v["caller"], "target": v["target"]} for k, v in gw.pending.items()}

    @app.post("/approvals/{approval_id}")
    async def decide(approval_id: str, approve: bool = True):
        return await gw.decide(approval_id, approve)

    @app.get("/audit")
    async def audit(limit: int = 50):
        return gw.audit[-limit:]

    return app
