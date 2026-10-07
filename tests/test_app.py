"""API tests for the AgentShield Console web app (no browser needed)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

from agentshield.app import ALL_ON, app  # noqa: E402

ALL_OFF = {k: False for k in ALL_ON}


def test_console_end_to_end():
    with TestClient(app) as c:
        c.post("/api/reset", json={})
        assert c.get("/").status_code == 200
        o = c.get("/api/overview").json()
        assert {a["id"] for a in o["agents"]} == {"invoice_reader", "policy_checker", "payment_approver"}

        samples = c.get("/api/samples").json()
        normal = next(s for s in samples if s["label"] == "Normal invoice")
        r = c.post("/api/invoice", json={"text": normal["text"]}).json()
        assert r["outcome"]["status"] == "paid"
        assert len(r["calls"]) == 3 and all(x["decision"] == "allowed" for x in r["calls"])
        assert any(ch["key"] == "human_approval" and ch["status"] == "passed" for ch in r["calls"][2]["checks"])

        hinglish = next(s for s in samples if s["label"] == "Injection: hinglish")
        r = c.post("/api/invoice", json={"text": hinglish["text"]}).json()
        assert r["outcome"]["status"] == "blocked_by_gateway"
        assert r["calls"][0]["failed_check"] == "injection_scan"

        large = next(s for s in samples if s["label"].startswith("Large payment"))
        assert c.post("/api/invoice", json={"text": large["text"]}).json()["outcome"]["status"] == "held_for_human"
        pending = c.get("/api/approvals").json()
        assert len(pending) == 1
        assert c.post(f"/api/approvals/{pending[0]['id']}", json={"approve": True}).json()["status"] == "paid"

        audit = c.get("/api/audit").json()
        assert {"allowed", "blocked", "held"} <= {a["decision"] for a in audit}


def test_every_attack_is_stopped_with_defences_on_and_lands_with_them_off():
    with TestClient(app) as c:
        for name in ["injection", "hijack", "spoof", "tamper", "pii", "large", "flood"]:
            on = c.post(f"/api/attacks/{name}", json={"defences": ALL_ON}).json()
            off = c.post(f"/api/attacks/{name}", json={"defences": ALL_OFF}).json()
            assert on["succeeded"] is False, name
            assert off["succeeded"] is True, name
        # agents refuse direct calls whatever the gateway settings
        assert c.post("/api/attacks/bypass", json={"defences": ALL_OFF}).json()["succeeded"] is False


def test_defence_toggles_change_the_main_network():
    with TestClient(app) as c:
        c.post("/api/reset", json={})
        o = c.post("/api/defences", json={"request_scan": False}).json()
        assert o["defences"]["request_scan"] is False
        c.post("/api/reset", json={})
