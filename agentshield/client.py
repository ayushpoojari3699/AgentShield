"""Send an invoice through the live network started with `python -m agentshield.serve`.

    python -m agentshield.client samples/invoice_ok.txt
    python -m agentshield.client samples/invoice_large.txt
    python -m agentshield.client --approve <approval_id>
    python -m agentshield.client --audit
"""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

import httpx

from .a2a import A2AClient
from .gateway import dev_key
from .network import process_invoice

DEFAULT_GATEWAY = "http://127.0.0.1:8100"


async def main(args):
    if args.audit:
        r = httpx.get(f"{args.gateway}/audit", params={"limit": 10})
        for rec in r.json():
            print(json.dumps(rec))
        return
    if args.approve:
        r = httpx.post(f"{args.gateway}/approvals/{args.approve}", params={"approve": "true"})
        print(json.dumps(r.json(), indent=2))
        return
    client = A2AClient(headers={"X-Agent-Id": "coordinator", "X-Agent-Key": dev_key("coordinator")})
    out = await process_invoice(client, Path(args.invoice).read_text(encoding="utf-8"), args.gateway)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("invoice", nargs="?", help="path to an invoice text file")
    p.add_argument("--gateway", default=DEFAULT_GATEWAY)
    p.add_argument("--approve", metavar="APPROVAL_ID", help="approve a payment held for a human")
    p.add_argument("--audit", action="store_true", help="show the last 10 audit records")
    a = p.parse_args()
    if not (a.invoice or a.approve or a.audit):
        p.error("give an invoice file, --approve ID or --audit")
    asyncio.run(main(a))
