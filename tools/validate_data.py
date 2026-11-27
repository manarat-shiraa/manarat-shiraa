"""فاحص ملفات الفريق: يتأكد إن ملفات البيانات والقواعد مطابقة للعقد قبل ما ندمجها.

التشغيل من مجلد mursad (والبيئة مفعّلة):
    python tools/validate_data.py
أو لفحص ملف جديد قبل ما تحطه مكان القديم:
    python tools/validate_data.py --alerts "C:/path/to/khalid_alerts.json"
    python tools/validate_data.py --network new_network.json --rules new_rules.json --mitre new_mitre.json

النتيجة:
    ❌ خطأ   = لازم يتصلّح، النظام ما يشتغل صح بدونه
    ⚠️ تنبيه = يشتغل، بس فيه شي ناقص أو غير مربوط
    وفي الآخر: دقة النظام مقارنة بالإجابات المتوقعة (expected_severity / expected_false_positive) لو موجودة
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEVELS = ["low", "medium", "high", "critical"]
SOURCE_TYPES = {"endpoint", "firewall", "network", "server", "identity", "email", "ids", "siem"}
MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
ALERT_REQUIRED = ["id", "timestamp", "host", "rule_name"]
ALERT_RECOMMENDED = ["source", "user", "src_ip", "dest_ip", "raw_log"]
# أقصى طول مسموح للنصوص (بالحروف)، حتى ما يتعطل النموذج أو العرض بنص ضخم
MAX_LEN = {"id": 40, "host": 60, "user": 60, "rule_name": 120, "raw_log": 2000}


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)


def load_json(path: Path, rep: Report, label: str):
    if not path.exists():
        rep.error(f"[{label}] الملف غير موجود: {path}")
        return None
    if path.stat().st_size == 0:
        rep.error(f"[{label}] الملف فاضي: {path}")
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as e:
        rep.error(f"[{label}] صيغة JSON غير صحيحة في السطر {e.lineno} العمود {e.colno}: {e.msg}")
        return None


def check_mitre(mitre: dict, rep: Report) -> set[str]:
    ids = {k for k in mitre if not k.startswith("_")}
    for t in ids:
        if not MITRE_RE.match(t):
            rep.error(f"[MITRE] رقم تقنية غير صحيح: {t} (الشكل الصحيح مثل T1059 أو T1059.001)")
        elif not mitre[t].get("ar") or not mitre[t].get("en"):
            rep.warn(f"[MITRE] التقنية {t} ناقصها الاسم العربي أو الإنجليزي")
    return ids


def check_rules(rules: dict, mitre_ids: set[str], rep: Report) -> set[str]:
    names = set(rules.get("rules", {}))
    for name, r in rules.get("rules", {}).items():
        if r.get("base_severity") not in LEVELS:
            rep.error(f"[القواعد] '{name}': base_severity لازم يكون واحد من {LEVELS}")
        if r.get("max_severity") and r["max_severity"] not in LEVELS:
            rep.error(f"[القواعد] '{name}': max_severity غير صحيح")
        for t in r.get("mitre", []):
            if t not in mitre_ids:
                rep.warn(f"[القواعد] '{name}': التقنية {t} مو موجودة في ملف MITRE (عبدالله)")
    for key in ("escalation", "correlation", "default"):
        if key not in rules:
            rep.error(f"[القواعد] القسم '{key}' ناقص")
    return names


def check_network(net: dict, mitre_ids: set[str], rep: Report) -> set[str]:
    assets = net.get("assets", [])
    ids = [a.get("id") for a in assets]
    asset_ids = set(ids)
    for dup in {i for i in ids if ids.count(i) > 1}:
        rep.error(f"[الشبكة] جهاز مكرر: {dup}")
    for a in assets:
        if not isinstance(a.get("criticality"), int) or not 1 <= a["criticality"] <= 5:
            rep.error(f"[الشبكة] {a.get('id')}: criticality لازم رقم من 1 إلى 5")
        if not a.get("label"):
            rep.warn(f"[الشبكة] {a.get('id')}: ما له اسم عربي (label)")
    if not any(a.get("crown_jewel") for a in assets):
        rep.error("[الشبكة] لازم يكون فيه أصل حرج واحد على الأقل (crown_jewel: true)")
    edge_ids = [e.get("id") for e in net.get("edges", [])]
    for dup in {i for i in edge_ids if edge_ids.count(i) > 1}:
        rep.error(f"[الشبكة] رقم حافة مكرر: {dup}")
    for e in net.get("edges", []):
        for end in ("from", "to"):
            if e.get(end) not in asset_ids:
                rep.error(f"[الشبكة] الحافة {e.get('id')}: الجهاز '{e.get(end)}' مو موجود في الأجهزة")
        d = e.get("difficulty")
        if not isinstance(d, (int, float)) or not 0 <= d <= 1:
            rep.error(f"[الشبكة] الحافة {e.get('id')}: difficulty لازم رقم بين 0 و 1")
        if e.get("mitre") and e["mitre"] not in mitre_ids:
            rep.warn(f"[الشبكة] الحافة {e.get('id')}: التقنية {e['mitre']} مو موجودة في ملف MITRE")
        if not e.get("fix"):
            rep.warn(f"[الشبكة] الحافة {e.get('id')}: ما فيها طريقة إصلاح (fix)")
    for ep in net.get("entry_points", []):
        if ep.get("asset") not in asset_ids:
            rep.error(f"[الشبكة] نقطة الدخول '{ep.get('asset')}' مو موجودة في الأجهزة")
    return asset_ids


def check_alerts(alerts, asset_ids: set[str], rule_names: set[str], rep: Report) -> None:
    if not isinstance(alerts, list):
        rep.error("[التنبيهات] الملف لازم يكون قائمة [ ... ] من التنبيهات")
        return
    ids = [a.get("id") for a in alerts]
    for dup in {i for i in ids if ids.count(i) > 1}:
        rep.error(f"[التنبيهات] رقم تنبيه مكرر: {dup}")
    unknown_hosts, unknown_rules = set(), set()
    for a in alerts:
        aid = a.get("id") or a.get("alert_id") or "؟"
        for f in ALERT_REQUIRED:
            if not a.get(f):
                rep.error(f"[التنبيهات] {aid}: الحقل '{f}' ناقص أو فاضي")
        for f in ALERT_RECOMMENDED:
            if f not in a:
                rep.warn(f"[التنبيهات] {aid}: الحقل '{f}' ناقص (مستحسن)")
        for old, new in (("alert_id", "id"), ("title", "rule_name"), ("severity", "expected_severity"),
                         ("is_false_positive", "expected_false_positive")):
            if old in a:
                rep.warn(f"[التنبيهات] {aid}: الحقل '{old}' اسمه القديم، المتفق عليه '{new}'")
        for f, limit in MAX_LEN.items():
            if len(str(a.get(f, ""))) > limit:
                rep.error(f"[التنبيهات] {aid}: الحقل '{f}' أطول من المسموح ({len(str(a[f]))} حرفاً، الحد {limit})")
        try:
            datetime.fromisoformat(str(a.get("timestamp", "")).replace("Z", "+00:00"))
        except ValueError:
            rep.error(f"[التنبيهات] {aid}: الوقت بصيغة غلط '{a.get('timestamp')}' (المطلوب مثل 2026-11-15T10:02:00Z)")
        if a.get("host") and a["host"] not in asset_ids:
            unknown_hosts.add(a["host"])
        if a.get("rule_name") and a["rule_name"] not in rule_names:
            unknown_rules.add(a["rule_name"])
        if "expected_severity" in a and str(a["expected_severity"]).lower() not in LEVELS:
            rep.error(f"[التنبيهات] {aid}: expected_severity لازم واحد من {LEVELS}")
        if "source_type" in a and a["source_type"] not in SOURCE_TYPES:
            rep.warn(f"[التنبيهات] {aid}: source_type '{a['source_type']}' غير معروف. المتاح: {sorted(SOURCE_TYPES)}")
    for h in sorted(unknown_hosts):
        rep.error(f"[الربط] الجهاز '{h}' في التنبيهات مو موجود في الشبكة، فما يرتبط بالظل الرقمي (خالد: صحح الاسم أو أضفه للشبكة)")
    for r in sorted(unknown_rules):
        rep.warn(f"[الربط] القاعدة '{r}' ما لها خطورة في ملف القواعد، فبتاخذ الخطورة الافتراضية (براء)")


def accuracy(alerts: list[dict], net: dict, rules_path: Path, mitre_path: Path) -> None:
    """يشغّل النظام على التنبيهات ويقارن النتيجة بإجابات خالد المتوقعة."""
    expected = [a for a in alerts if "expected_severity" in a or "expected_false_positive" in a]
    if not expected:
        print("\nℹ️ ما فيه إجابات متوقعة (expected_*) في التنبيهات، فتخطينا قياس الدقة.")
        return
    sys.path.insert(0, str(ROOT / "backend"))
    from app import config  # noqa: E402

    config.SEVERITY_RULES_FILE = rules_path
    config.MITRE_FILE = mitre_path
    from app.mursad import Mursad  # noqa: E402
    from app.shadow import DigitalShadow  # noqa: E402

    results = {r["alert_id"]: r for r in Mursad(DigitalShadow(net)).analyze_all(alerts)}
    sev_ok = sev_total = fp_ok = fp_total = 0
    misses = []
    for a in expected:
        r = results[a["id"]]
        if "expected_severity" in a:
            sev_total += 1
            if r["severity"] == str(a["expected_severity"]).lower():
                sev_ok += 1
            else:
                misses.append(f"  {a['id']}: المتوقع {a['expected_severity']}، والنظام طلّع {r['severity']}")
        if "expected_false_positive" in a:
            fp_total += 1
            if bool(r["likely_false_positive"]) == bool(a["expected_false_positive"]):
                fp_ok += 1
            else:
                misses.append(f"  {a['id']}: الإنذار الكاذب المتوقع {a['expected_false_positive']}، والنظام {r['likely_false_positive']}")
    print("\n📊 دقة النظام مقارنة بالإجابات المتوقعة:")
    if sev_total:
        print(f"  الخطورة: {sev_ok}/{sev_total} ({round(100 * sev_ok / sev_total)}٪)")
    if fp_total:
        print(f"  كشف الإنذارات الكاذبة: {fp_ok}/{fp_total} ({round(100 * fp_ok / fp_total)}٪)")
    if misses:
        print("  الاختلافات (راجعوها مع براء وخالد):")
        print("\n".join(misses[:20]))


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(description="فحص ملفات بيانات وقواعد مرصاد")
    p.add_argument("--alerts", default=ROOT / "data" / "alerts.json", type=Path)
    p.add_argument("--network", default=ROOT / "data" / "network.json", type=Path)
    p.add_argument("--rules", default=ROOT / "rules" / "severity_rules.json", type=Path)
    p.add_argument("--mitre", default=ROOT / "rules" / "mitre_mapping.json", type=Path)
    p.add_argument("--no-accuracy", action="store_true", help="بدون قياس الدقة")
    args = p.parse_args()

    rep = Report()
    mitre = load_json(args.mitre, rep, "MITRE")
    rules = load_json(args.rules, rep, "القواعد")
    net = load_json(args.network, rep, "الشبكة")
    alerts = load_json(args.alerts, rep, "التنبيهات")

    mitre_ids = check_mitre(mitre, rep) if mitre else set()
    rule_names = check_rules(rules, mitre_ids, rep) if rules else set()
    asset_ids = check_network(net, mitre_ids, rep) if net else set()
    if alerts is not None:
        check_alerts(alerts, asset_ids, rule_names, rep)

    print("فحص ملفات مرصاد")
    print("=" * 40)
    for e in rep.errors:
        print("❌", e)
    for w in rep.warnings:
        print("⚠️ ", w)
    print("=" * 40)
    print(f"الأخطاء: {len(rep.errors)}   التنبيهات: {len(rep.warnings)}")

    if rep.errors:
        print("❌ الملفات غير جاهزة. صلّحوا الأخطاء أول.")
        return 1
    print("✅ الملفات مطابقة للعقد وجاهزة للدمج.")
    if not args.no_accuracy and isinstance(alerts, list) and net and rules and mitre:
        accuracy(alerts, net, args.rules, args.mitre)
    return 0


if __name__ == "__main__":
    sys.exit(main())
