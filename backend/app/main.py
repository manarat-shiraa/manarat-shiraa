"""واجهة برمجة مرصاد + الظل الرقمي (FastAPI).

التشغيل من مجلد backend:
    uvicorn app.main:app --reload --port 8000
والتوثيق التفاعلي على: http://localhost:8000/docs
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from . import config
from .mursad import Mursad
from .shadow import DigitalShadow

app = FastAPI(title="مرصاد + الظل الرقمي", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_lock = threading.Lock()
shadow = DigitalShadow.from_file(config.NETWORK_FILE)
mursad = Mursad(shadow)
alerts: list[dict] = json.loads(config.ALERTS_FILE.read_text(encoding="utf-8"))


class FixRequest(BaseModel):
    edge_id: str


class WhatIfRequest(BaseModel):
    fixed_edges: list[str]


# ---------- عام ----------
@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "llm_provider": config.LLM_PROVIDER, "alerts": len(alerts), "assets": len(shadow.assets)}


# ---------- الظل الرقمي ----------
@app.get("/api/network")
def network() -> dict:
    """الشبكة كاملة للرسم: الأجهزة والحواف ونقاط الدخول والأصول الحرجة."""
    return {
        "assets": list(shadow.assets.values()),
        "edges": [dict(e, fixed=e["id"] in shadow.fixed_edges) for e in shadow.edge_index.values()],
        "entry_points": shadow.network["entry_points"],
        "crown_jewels": shadow.crown_jewels,
    }


@app.get("/api/shadow/analysis")
def shadow_analysis() -> dict:
    return shadow.analysis()


@app.post("/api/shadow/whatif")
def shadow_whatif(req: WhatIfRequest) -> dict:
    """محاكاة إصلاحات بدون ما تنحفظ."""
    unknown = [e for e in req.fixed_edges if e not in shadow.edge_index]
    if unknown:
        raise HTTPException(404, f"حواف غير معروفة: {unknown}")
    return shadow.analysis(set(req.fixed_edges))


@app.post("/api/shadow/fix")
def shadow_fix(req: FixRequest) -> dict:
    """تطبيق إصلاح على الظل الرقمي (يأثر على تحليل التنبيهات بعدها)."""
    if req.edge_id not in shadow.edge_index:
        raise HTTPException(404, "حافة غير معروفة")
    with _lock:
        shadow.fixed_edges.add(req.edge_id)
    return shadow.analysis()


@app.post("/api/shadow/reset")
def shadow_reset() -> dict:
    with _lock:
        shadow.fixed_edges.clear()
    return shadow.analysis()


# ---------- مرصاد ----------
@app.get("/api/alerts")
def list_alerts() -> list[dict]:
    return mursad.analyze_all(alerts)


@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str, llm: bool = True) -> dict:
    """تفاصيل تنبيه واحد مع الشرح (بالنموذج لو مفعّل)."""
    alert = next((a for a in alerts if a["id"] == alert_id), None)
    if alert is None:
        raise HTTPException(404, "تنبيه غير موجود")
    analyzed = {r["alert_id"]: r for r in mursad.analyze_all(alerts)}[alert_id]
    if llm and config.LLM_PROVIDER != "none":
        detailed = mursad.analyze_alert(alert, use_llm=True)
        analyzed["explanation_ar"] = detailed["explanation_ar"]
        analyzed["explanation_source"] = detailed["explanation_source"]
    return analyzed


@app.get("/api/incidents")
def list_incidents(llm: bool = False) -> list[dict]:
    return mursad.incidents(alerts, use_llm=llm)


@app.get("/api/incidents/{incident_id}/summary")
def incident_summary(incident_id: str, llm: bool = True) -> dict:
    """ملخص حادثة واحدة: بالنموذج (llm=true) أو بقالب القواعد (llm=false)."""
    inc = next((i for i in mursad.incidents(alerts, use_llm=False) if i["id"] == incident_id), None)
    if inc is None:
        raise HTTPException(404, "حادثة غير موجودة")
    text, source = mursad._incident_summary(inc, llm and config.LLM_PROVIDER != "none")
    return {"incident_id": incident_id, "summary_ar": text, "summary_source": source}


@app.post("/api/alerts/ingest")
def ingest(payload: dict) -> dict:
    """استقبال تنبيه من Splunk (Webhook Alert Action) أو بصيغتنا مباشرة.

    Splunk يرسل: {"search_name": "...", "result": {"host": "...", ...}}
    """
    if "result" in payload:
        res = payload["result"]
        alert = {
            "id": f"S-{len(alerts) + 1:03d}",
            "timestamp": res.get("_time") or datetime.now(timezone.utc).isoformat(),
            "source": "splunk",
            "host": res.get("host", ""),
            "src_ip": res.get("src_ip") or res.get("src", ""),
            "dest_ip": res.get("dest_ip") or res.get("dest", ""),
            "user": res.get("user", ""),
            "rule_name": payload.get("search_name", res.get("rule_name", "")),
            "raw_log": res.get("_raw", ""),
        }
    else:
        required = {"host", "rule_name"}
        if not required <= payload.keys():
            raise HTTPException(422, f"حقول ناقصة: {sorted(required - payload.keys())}")
        alert = {
            "id": payload.get("id") or f"S-{len(alerts) + 1:03d}",
            "timestamp": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            "source": payload.get("source", "api"),
            **{k: payload.get(k, "") for k in ("host", "src_ip", "dest_ip", "user", "rule_name", "raw_log")},
        }
    with _lock:
        alerts.append(alert)
    return mursad.analyze_alert(alert)
