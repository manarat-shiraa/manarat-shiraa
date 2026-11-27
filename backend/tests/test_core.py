"""اختبارات أساسية. التشغيل من مجلد backend:  pytest -q"""
import json

from fastapi.testclient import TestClient

from app import config
from app.main import app
from app.mursad import Mursad
from app.shadow import DigitalShadow

client = TestClient(app)


def load():
    shadow = DigitalShadow.from_file(config.NETWORK_FILE)
    alerts = json.loads(config.ALERTS_FILE.read_text(encoding="utf-8"))
    return shadow, Mursad(shadow), alerts


def by_rule_host(alerts, rule, host):
    return next(a for a in alerts if a["rule_name"] == rule and a["host"] == host)


# ---------- الظل الرقمي ----------
def test_paths_exist_and_sorted():
    shadow, _, _ = load()
    paths = shadow.attack_paths()
    assert paths
    probs = [p.probability for p in paths]
    assert probs == sorted(probs, reverse=True)
    assert all(p.target in shadow.crown_jewels for p in paths)


def test_min_cut_blocks_everything():
    shadow, _, _ = load()
    cut = set(shadow.min_cut_edges())
    assert cut
    assert shadow.attack_paths(cut) == []
    assert shadow.risk_score(cut) == 0


def test_fix_reduces_risk():
    shadow, _, _ = load()
    top = shadow.recommendations()[0]
    assert shadow.risk_score({top["edge_id"]}) < shadow.risk_score(set())


# ---------- دقة مرصاد مقارنة بالإجابات المتوقعة ----------
def test_accuracy_against_expected_answers():
    _, mursad, alerts = load()
    results = {r["alert_id"]: r for r in mursad.analyze_all(alerts)}
    for a in alerts:
        r = results[a["id"]]
        if "expected_severity" in a:
            assert r["severity"] == a["expected_severity"], f"{a['id']} {a['rule_name']}"
        if "expected_false_positive" in a:
            assert r["likely_false_positive"] == a["expected_false_positive"], f"{a['id']} {a['rule_name']}"


# ---------- الاستثناءات: نفس القاعدة، نتيجة مختلفة حسب السياق ----------
def test_exceptions_separate_lookalikes():
    _, mursad, alerts = load()
    nessus = mursad.analyze_alert(next(a for a in alerts if a["rule_name"] == "Port Scan Detected" and a["src_ip"] == "10.0.5.10"))
    attacker = mursad.analyze_alert(next(a for a in alerts if a["rule_name"] == "Port Scan Detected" and a["src_ip"] != "10.0.5.10"))
    assert nessus["likely_false_positive"] and nessus["exception_id"] == "EX-01"
    assert not attacker["likely_false_positive"]

    crowdstrike = mursad.analyze_alert(by_rule_host(alerts, "LSASS Memory Access", "PC-IT-ADMIN"))
    mimikatz = mursad.analyze_alert(by_rule_host(alerts, "LSASS Memory Access", "FILE-SRV"))
    assert crowdstrike["likely_false_positive"]
    assert not mimikatz["likely_false_positive"]

    forgot_password = mursad.analyze_alert(by_rule_host(alerts, "Multiple Failed Logins", "VPN-GW"))
    brute_force = mursad.analyze_alert(by_rule_host(alerts, "Multiple Failed Logins", "FILE-SRV"))
    assert forgot_password["likely_false_positive"]
    assert not brute_force["likely_false_positive"] and brute_force["severity"] == "high"


def test_duplicates_are_merged():
    _, mursad, alerts = load()
    results = mursad.analyze_all(alerts)
    dups = [r for r in results if r["duplicate_of"]]
    assert len(dups) == 2
    original = next(r for r in results if r["alert_id"] == dups[0]["duplicate_of"])
    assert original["duplicates"] == 2


# ---------- الحوادث والأسئلة الخمسة ----------
def test_attack_story_is_one_critical_incident_with_five_w():
    _, mursad, alerts = load()
    top = mursad.incidents(alerts)[0]
    assert top["severity"] == "critical"
    assert {"MAIL-SRV", "PC-SALES-07", "FILE-SRV", "PC-IT-ADMIN", "DC-01", "DB-CUSTOMERS"} <= set(top["hosts"])
    w = top["five_w"]
    assert "ahmed" in w["who"]["users"]
    assert w["when"]["duration_minutes"] > 0
    assert w["how"]["entry_vector"]
    assert w["why"] and w["what"]
    assert "185.220.101.4" in w["who"]["suspicious_ips"]


def test_false_positives_never_join_incidents():
    _, mursad, alerts = load()
    analyzed = {r["alert_id"]: r for r in mursad.analyze_all(alerts)}
    for inc in mursad.incidents(alerts):
        for step in inc["timeline"]:
            assert not analyzed[step["alert_id"]]["likely_false_positive"]


# ---------- الواجهات البرمجية ----------
def test_api_endpoints():
    assert client.get("/api/health").json()["status"] == "ok"
    assert len(client.get("/api/alerts").json()) >= 20
    analysis = client.get("/api/shadow/analysis").json()
    assert analysis["risk_current"] > 0
    whatif = client.post("/api/shadow/whatif", json={"fixed_edges": analysis["min_cut_edges"]}).json()
    assert whatif["risk_current"] == 0
    assert client.get("/api/alerts/A-001").json()["alert_id"] == "A-001"
    assert "five_w" in client.get("/api/incidents").json()[0]


def test_ingest_splunk_webhook():
    r = client.post(
        "/api/alerts/ingest",
        json={"search_name": "Multiple Failed Logins", "result": {"host": "APP-SRV", "user": "svc_app", "_raw": "test"}},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["host"] == "APP-SRV" and body["on_attack_path"]


def test_incident_summary_endpoint_modes(monkeypatch):
    """مفتاح مع/بدون الذكاء الاصطناعي: القالب دائماً يشتغل، والنموذج لو فشل يرجع للقالب."""
    from fastapi.testclient import TestClient
    from app import config, llm_client
    from app.main import app

    client = TestClient(app)
    off = client.get("/api/incidents/INC-001/summary?llm=false").json()
    assert off["summary_source"] == "template" and off["summary_ar"]

    monkeypatch.setattr(config, "LLM_PROVIDER", "ollama")
    monkeypatch.setattr(config, "OLLAMA_URL", "http://127.0.0.1:9")
    monkeypatch.setattr(config, "LLM_TIMEOUT", 1)
    down = client.get("/api/incidents/INC-001/summary?llm=true").json()
    assert down["summary_source"] == "template" and down["summary_ar"] == off["summary_ar"]

    monkeypatch.setattr(llm_client, "generate", lambda prompt, fallback, max_tokens=400: ("ملخص من النموذج", "ollama"))
    on = client.get("/api/incidents/INC-001/summary?llm=true").json()
    assert on["summary_source"] == "ollama" and on["summary_ar"] == "ملخص من النموذج"
    assert client.get("/api/incidents/INC-999/summary").status_code == 404
