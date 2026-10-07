"""Wire everything together: agents, gateway, and the coordinator workflow.

`build_network()` creates an in-process network (no ports needed) that tests, the demo
and the benchmark use. `scripts/serve.py` runs the same pieces as real HTTP servers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import a2a
from .a2a import A2AClient, A2AError, LocalRouter, create_agent_app, data_part, make_message, text_part
from .agents import AgentContext, InvoiceReader, PaymentApprover, PolicyChecker, RogueAgent
from .detector import Detector, load_or_train
from .gateway import (GATEWAY_TOKEN_HEADER, Gateway, Policy, create_gateway_app, dev_key,
                      gateway_token)

GATEWAY_URL = "http://gateway"
HOSTS = {"invoice_reader": "invoice-reader", "policy_checker": "policy-checker",
         "payment_approver": "payment-approver", "rogue": "rogue-agent"}


@dataclass
class Network:
    gateway: Gateway
    router: LocalRouter
    reader: InvoiceReader
    checker: PolicyChecker
    approver: PaymentApprover
    rogue: RogueAgent
    apps: dict = field(default_factory=dict)

    def client(self, agent_id: str = "coordinator", key: str | None = None) -> A2AClient:
        return A2AClient(transport=self.router,
                         headers={"X-Agent-Id": agent_id, "X-Agent-Key": key if key is not None else dev_key(agent_id)})


async def build_network(detector: Detector | None = None, vulnerable_reader: bool = False,
                        policy_path: Path | None = None, audit_path: Path | None = None,
                        **policy_overrides) -> Network:
    policy = Policy.load(policy_path, **policy_overrides) if policy_path else Policy.load(**policy_overrides)
    router = LocalRouter({})
    reader = InvoiceReader(AgentContext("invoice_reader", GATEWAY_URL, router, dev_key("invoice_reader")),
                           vulnerable=vulnerable_reader)
    checker, approver, rogue = PolicyChecker(), PaymentApprover(), RogueAgent()
    token = (GATEWAY_TOKEN_HEADER, gateway_token())
    apps = {}
    for agent_id, agent in [("invoice_reader", reader), ("policy_checker", checker),
                            ("payment_approver", approver)]:
        apps[agent_id] = create_agent_app(agent.card(f"http://{HOSTS[agent_id]}{a2a.RPC_PATH}"),
                                          agent.handle, require_header=token)
        router.add(HOSTS[agent_id], apps[agent_id])
    apps["rogue"] = create_agent_app(rogue.card(f"http://{HOSTS['rogue']}{a2a.RPC_PATH}"), rogue.handle)
    router.add(HOSTS["rogue"], apps["rogue"])

    gw = Gateway(policy=policy, detector=detector or load_or_train(), transport=router,
                 audit_path=audit_path)
    apps["gateway"] = create_gateway_app(gw, GATEWAY_URL)
    router.add("gateway", apps["gateway"])
    await gw.pin_all()
    return Network(gw, router, reader, checker, approver, rogue, apps)


# --------------------------------------------------------------------------- workflow
async def process_invoice(client: A2AClient, invoice_text: str, gateway_url: str = GATEWAY_URL) -> dict:
    """The coordinator: discover agents via the gateway, then read -> check -> pay."""
    trace = []

    async def call(agent_id: str, skill_id: str, parts: list[dict]) -> dict:
        card = await client.get_card(f"{gateway_url}/agents/{agent_id}")      # A2A discovery
        if skill_id not in a2a.card_skill_ids(card):
            raise A2AError(a2a.ERR_UNSUPPORTED_SKILL, f"{agent_id} lacks {skill_id}")
        result = await client.send(a2a.card_url(card), make_message(parts, skill_id=skill_id))
        trace.append({"agent": agent_id, "skill": skill_id,
                      "result": "task" if "task" in result else "message"})
        return result

    try:
        r = await call("invoice_reader", "extract_invoice", [text_part(invoice_text)])
        invoice = a2a.message_data(a2a.result_message(r))["invoice"]
        r = await call("policy_checker", "check_policy", [data_part({"invoice": invoice})])
        policy = a2a.message_data(a2a.result_message(r))["policy"]
        if not policy["approved"]:
            return {"status": "rejected_by_policy", "reasons": policy["reasons"], "trace": trace}
        r = await call("payment_approver", "approve_payment",
                       [data_part({"invoice": invoice, "policy": policy})])
        if "task" in r and r["task"]["status"]["state"] == a2a.TASK_INPUT_REQUIRED:
            info = a2a.message_data(a2a.result_message(r))
            return {"status": "held_for_human", "approval_id": info["approval_id"], "trace": trace}
        payment = a2a.message_data(a2a.result_message(r))["payment"]
        return {"status": "paid" if payment["status"] == "scheduled" else payment["status"],
                "payment": payment, "trace": trace}
    except A2AError as e:
        return {"status": "blocked_by_gateway", "reason": e.message, "detail": e.data, "trace": trace}
