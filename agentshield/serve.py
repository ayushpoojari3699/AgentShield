"""Run the whole network as real HTTP servers on your machine.

    python -m agentshield.serve
        gateway           http://127.0.0.1:8100   (audit: /audit, approvals: /approvals)
        invoice_reader    http://127.0.0.1:8101
        policy_checker    http://127.0.0.1:8102
        payment_approver  http://127.0.0.1:8103
        rogue agent       http://127.0.0.1:8104

Then, in a second terminal:
    python -m agentshield.client samples/invoice_ok.txt
"""

from __future__ import annotations

import asyncio
import threading
import time

import uvicorn

from . import a2a
from .agents import AgentContext, InvoiceReader, PaymentApprover, PolicyChecker, RogueAgent
from .detector import load_or_train
from .gateway import GATEWAY_TOKEN_HEADER, Gateway, Policy, create_gateway_app, dev_key, gateway_token

HOST = "127.0.0.1"
PORTS = {"gateway": 8100, "invoice_reader": 8101, "policy_checker": 8102,
         "payment_approver": 8103, "rogue": 8104}


def url(name: str) -> str:
    return f"http://{HOST}:{PORTS[name]}"


def _start(app, port: int) -> uvicorn.Server:
    server = uvicorn.Server(uvicorn.Config(app, host=HOST, port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    while not server.started:
        time.sleep(0.05)
    return server


def main():
    token = (GATEWAY_TOKEN_HEADER, gateway_token())
    reader = InvoiceReader(AgentContext("invoice_reader", url("gateway"), None, dev_key("invoice_reader")))
    agents = {"invoice_reader": reader, "policy_checker": PolicyChecker(),
              "payment_approver": PaymentApprover()}
    for name, agent in agents.items():
        _start(a2a.create_agent_app(agent.card(url(name) + a2a.RPC_PATH), agent.handle, require_header=token),
               PORTS[name])
    rogue = RogueAgent()
    _start(a2a.create_agent_app(rogue.card(url("rogue") + a2a.RPC_PATH), rogue.handle), PORTS["rogue"])

    policy = Policy.load()
    for name in policy.agents:
        policy.agents[name]["url"] = url(name)
    gw = Gateway(policy=policy, detector=load_or_train(), audit_path=None)
    asyncio.run(gw.pin_all())

    print("AgentShield network running:")
    for name in PORTS:
        print(f"  {name:<17} {url(name)}")
    print("Try:  python -m agentshield.client samples/invoice_ok.txt     (Ctrl+C to stop)")
    uvicorn.run(create_gateway_app(gw, url("gateway")), host=HOST, port=PORTS["gateway"], log_level="warning")


if __name__ == "__main__":
    main()
