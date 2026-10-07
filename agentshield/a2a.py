"""A small, dependency-light implementation of the core of the A2A protocol (v1.0).

What is implemented (JSON-RPC protocol binding):
    * Agent Card discovery at  GET /.well-known/agent-card.json
    * JSON-RPC 2.0 method      POST /a2a   {"method": "SendMessage", ...}
    * Message / Part / Task objects with ProtoJSON enum strings
      (ROLE_USER, ROLE_AGENT, TASK_STATE_COMPLETED, TASK_STATE_INPUT_REQUIRED, ...)

What is not implemented: streaming, push notifications, GetTask/CancelTask, gRPC and
HTTP+JSON bindings, security schemes. The goal is to show the protocol mechanics in a
few hundred readable lines; for production, use the official `a2a-sdk`.

Convention used in this project: the caller names the skill it wants in
`message.metadata.skillId` (A2A leaves skill selection to the agent).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

PROTOCOL_VERSION = "1.0"
CARD_PATH = "/.well-known/agent-card.json"
RPC_PATH = "/a2a"

ROLE_USER = "ROLE_USER"
ROLE_AGENT = "ROLE_AGENT"

TASK_COMPLETED = "TASK_STATE_COMPLETED"
TASK_INPUT_REQUIRED = "TASK_STATE_INPUT_REQUIRED"
TASK_REJECTED = "TASK_STATE_REJECTED"

# JSON-RPC error codes (-32000..-32099 are reserved for implementation-defined errors)
ERR_INVALID_REQUEST = -32600
ERR_METHOD_NOT_FOUND = -32601
ERR_INVALID_PARAMS = -32602
ERR_INTERNAL = -32603
ERR_UNSUPPORTED_SKILL = -32004


# --------------------------------------------------------------------------- objects
def new_id() -> str:
    return uuid.uuid4().hex


def text_part(text: str) -> dict:
    return {"text": text}


def data_part(data: dict) -> dict:
    return {"data": data, "mediaType": "application/json"}


def make_message(parts: list[dict], role: str = ROLE_USER, skill_id: str | None = None,
                 context_id: str | None = None, metadata: dict | None = None) -> dict:
    meta = dict(metadata or {})
    if skill_id:
        meta["skillId"] = skill_id
    msg = {"messageId": new_id(), "role": role, "parts": parts}
    if context_id:
        msg["contextId"] = context_id
    if meta:
        msg["metadata"] = meta
    return msg


def message_texts(message: dict) -> list[str]:
    return [p["text"] for p in message.get("parts", []) if isinstance(p.get("text"), str)]


def message_data(message: dict) -> dict:
    """Merge every data part of a message into one dict."""
    out: dict = {}
    for p in message.get("parts", []):
        if isinstance(p.get("data"), dict):
            out.update(p["data"])
    return out


def make_agent_card(name: str, description: str, url: str, skills: list[dict],
                    version: str = "0.1.0", organization: str = "AgentShield demo") -> dict:
    return {
        "name": name,
        "description": description,
        "version": version,
        "supportedInterfaces": [
            {"url": url, "protocolBinding": "JSONRPC", "protocolVersion": PROTOCOL_VERSION}
        ],
        "provider": {"organization": organization, "url": "https://github.com/ayushpoojari3699"},
        "capabilities": {"streaming": False, "pushNotifications": False},
        "defaultInputModes": ["text/plain", "application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": skills,
    }


def skill(id: str, name: str, description: str, tags: list[str] | None = None) -> dict:
    return {"id": id, "name": name, "description": description, "tags": tags or []}


def card_url(card: dict) -> str:
    return card["supportedInterfaces"][0]["url"]


def card_skill_ids(card: dict) -> set[str]:
    return {s["id"] for s in card.get("skills", [])}


# --------------------------------------------------------------------------- errors
class A2AError(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code, self.message, self.data = code, message, data

    def to_json(self) -> dict:
        err = {"code": self.code, "message": self.message}
        if self.data is not None:
            err["data"] = self.data
        return err


def rpc_result(req_id, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def rpc_error(req_id, err: A2AError) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": err.to_json()}


# --------------------------------------------------------------------------- server
Handler = Callable[[dict, dict], Awaitable[dict]]
"""async handler(message, request_context) -> result dict ({"message": ...} or {"task": ...})."""


def create_agent_app(card: dict, handler: Handler, require_header: tuple[str, str] | None = None) -> FastAPI:
    """Expose one agent: its Agent Card plus a JSON-RPC SendMessage endpoint.

    require_header=(name, value) makes the agent accept messages only when that header is
    present, e.g. a token that only the AgentShield gateway holds, so callers can't bypass it.
    """
    app = FastAPI(title=card["name"])
    app.state.card = card

    @app.get(CARD_PATH)
    async def agent_card():
        return app.state.card

    @app.post(RPC_PATH)
    async def rpc(request: Request):
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(rpc_error(None, A2AError(-32700, "Parse error")))
        req_id = body.get("id")
        try:
            if body.get("jsonrpc") != "2.0" or "method" not in body:
                raise A2AError(ERR_INVALID_REQUEST, "Invalid JSON-RPC request")
            if require_header and request.headers.get(require_header[0]) != require_header[1]:
                raise A2AError(-32001, "Direct calls are not accepted; go through the gateway")
            if body["method"] != "SendMessage":
                raise A2AError(ERR_METHOD_NOT_FOUND, f"Method {body['method']} not supported")
            message = (body.get("params") or {}).get("message")
            if not isinstance(message, dict) or not isinstance(message.get("parts"), list):
                raise A2AError(ERR_INVALID_PARAMS, "params.message with parts is required")
            ctx = {"headers": dict(request.headers), "card": app.state.card}
            return JSONResponse(rpc_result(req_id, await handler(message, ctx)))
        except A2AError as e:
            return JSONResponse(rpc_error(req_id, e))
        except Exception as e:  # never leak a stack trace to another agent
            return JSONResponse(rpc_error(req_id, A2AError(ERR_INTERNAL, f"Internal error: {type(e).__name__}")))

    return app


def reply(data: dict | None = None, text: str | None = None, context_id: str | None = None) -> dict:
    parts = []
    if text:
        parts.append(text_part(text))
    if data is not None:
        parts.append(data_part(data))
    return {"message": make_message(parts, role=ROLE_AGENT, context_id=context_id)}


def task_result(state: str, text: str, data: dict | None = None, task_id: str | None = None) -> dict:
    parts = [text_part(text)] + ([data_part(data)] if data else [])
    return {"task": {"id": task_id or new_id(), "contextId": new_id(),
                     "status": {"state": state,
                                "message": make_message(parts, role=ROLE_AGENT)}}}


# --------------------------------------------------------------------------- client
class LocalRouter(httpx.AsyncBaseTransport):
    """Route http://<host>/... to in-process ASGI apps (tests, benchmark, demo).

    In live mode the same code talks to real servers over HTTP instead.
    """

    def __init__(self, apps: dict[str, Any]):
        self._transports = {host: httpx.ASGITransport(app=app) for host, app in apps.items()}

    def add(self, host: str, app) -> None:
        self._transports[host] = httpx.ASGITransport(app=app)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        t = self._transports.get(request.url.host)
        if t is None:
            raise httpx.ConnectError(f"No route to {request.url.host}", request=request)
        return await t.handle_async_request(request)


@dataclass
class A2AClient:
    """Minimal A2A client: discover an Agent Card and send messages."""

    transport: httpx.AsyncBaseTransport | None = None
    headers: dict = field(default_factory=dict)
    timeout: float = 30.0

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=self.transport, timeout=self.timeout,
                                 headers={"A2A-Version": PROTOCOL_VERSION, **self.headers})

    async def get_card(self, base_url: str) -> dict:
        async with self._client() as c:
            r = await c.get(base_url.rstrip("/") + CARD_PATH)
            if r.status_code == 404:
                raise A2AError(-32003, f"No trusted agent card at {base_url} (unknown or quarantined)")
            r.raise_for_status()
            return r.json()

    async def send(self, endpoint_url: str, message: dict) -> dict:
        """POST SendMessage; return the JSON-RPC result or raise A2AError."""
        body = {"jsonrpc": "2.0", "id": new_id(), "method": "SendMessage",
                "params": {"message": message}}
        async with self._client() as c:
            r = await c.post(endpoint_url, json=body)
            r.raise_for_status()
            payload = r.json()
        if "error" in payload:
            e = payload["error"]
            raise A2AError(e.get("code", ERR_INTERNAL), e.get("message", "error"), e.get("data"))
        return payload["result"]


def result_message(result: dict) -> dict:
    """The message carried by a result, whether it is a Message or a Task."""
    if "message" in result:
        return result["message"]
    return result["task"]["status"]["message"]
