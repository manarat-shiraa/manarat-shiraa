"""مرصاد: تحليل التنبيهات، وربطها بالظل الرقمي، وجمعها في حوادث.

ترتيب التحليل لكل تنبيه:
1. الخطورة الأساسية من قواعد براء (rules/severity_rules.json)
2. تقنيات MITRE ATT&CK من خريطة عبدالله (rules/mitre_mapping.json)
3. الإثراء: سمعة عناوين الـ IP
4. سياق الظل الرقمي: هل الجهاز على مسار هجوم؟ وكم خطوة عن الأصل الحرج؟
5. رفع الأولوية حسب القاعدة، مع سبب مكتوب لكل تعديل
6. الشرح والتقرير بالعربي (نموذج ذكاء اصطناعي أو قالب جاهز)
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from . import config, llm_client
from .enrich import enrich_ips
from .shadow import DigitalShadow

LEVELS = ["low", "medium", "high", "critical"]
LEVELS_AR = {"low": "منخفضة", "medium": "متوسطة", "high": "عالية", "critical": "حرجة"}
PHASES_AR = {
    "Reconnaissance": "استطلاع", "Initial Access": "وصول أولي", "Execution": "تنفيذ", "Persistence": "استمرارية",
    "Privilege Escalation": "تصعيد صلاحيات", "Defense Evasion": "تخفي", "Credential Access": "سرقة بيانات الدخول",
    "Discovery": "استكشاف", "Lateral Movement": "تحرك جانبي", "Collection": "جمع بيانات",
    "Command and Control": "قيادة وتحكم", "Exfiltration": "تسريب بيانات", "Impact": "تخريب",
}


def _load(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _bump(level: str, steps: int) -> str:
    return LEVELS[min(LEVELS.index(level) + steps, len(LEVELS) - 1)]


def _count(n: int, one: str, two: str, few: str, many: str) -> str:
    """صيغة العدد بالعربي: تنبيه واحد / تنبيهين / 3 تنبيهات / 11 تنبيهاً."""
    if n == 1:
        return one
    if n == 2:
        return two
    return f"{n} {few if 3 <= n <= 10 else many}"


def _ts(alert: dict) -> datetime:
    return datetime.fromisoformat(alert["timestamp"].replace("Z", "+00:00"))


# أمر المكوّن الذكي (أجزاؤه الستة: الدور، السياق، المهمة، القيود، صيغة المخرج، المثال)
INCIDENT_PROMPT = """الدور: أنت محلل أمني مساعد في مركز عمليات أمنية، تكتب بالعربي الواضح.
السياق: وصلتك حادثة مجمّعة من تنبيهات مترابطة، صنّفتها القواعد والرسم البياني. الحقائق أدناه (الخطورة، الأجهزة، المستخدمون، تقنيات MITRE، الخط الزمني، مسار الهجوم) مصدرك الوحيد.
المهمة: اكتب ملخصاً للحادثة بترتيب زمني: ماذا حدث، ثم الخطوة المتوقعة التالية للمهاجم إن وُجدت.
القيود: بحد أقصى 4 جمل. لا تذكر جهازاً أو مستخدماً أو تقنية غير موجودة في الحقائق. لا تغيّر الخطورة ولا تقترح استبعاد تنبيه. وإن لم تعرف فقل «غير متوفر».
صيغة المخرج: فقرة عربية، بلا عناوين ولا نقاط.
المثال: «بدأت الحادثة بإيميل تصيّد وصل إلى خادم البريد، ثم تحرك المهاجم إلى جهاز المبيعات 07 وخادم الملفات حتى وحدة التحكم بالنطاق. المسار ينتهي عند قاعدة بيانات العملاء، والأولوية احتواء الحادثة ومنع التسريب.»
الحقائق:
{facts}"""



class Mursad:
    def __init__(self, shadow: DigitalShadow):
        self.shadow = shadow
        self.rules = _load(config.SEVERITY_RULES_FILE)
        self.mitre = {k: v for k, v in _load(config.MITRE_FILE).items() if not k.startswith("_")}

    # ---------- تنبيه واحد ----------
    def analyze_alert(self, alert: dict, use_llm: bool = False) -> dict:
        rule = self.rules["rules"].get(alert.get("rule_name", ""), self.rules["default"])
        esc = self.rules["escalation"]
        base = rule["base_severity"]
        severity = base
        reasons: list[str] = []
        fp = bool(rule.get("likely_false_positive"))
        exception = self._match_exception(alert)
        if exception:
            fp = True

        ctx = self.shadow.host_context(alert.get("host", ""))
        intel = enrich_ips(alert.get("src_ip", ""), alert.get("dest_ip", ""))

        if exception:
            reasons.append(f"مطابق للاستثناء {exception['id']}: {exception['reason']}. التنبيه محفوظ للمراجعة، لكن ما ترتفع أولويته.")
        elif fp and esc.get("skip_likely_false_positive", True):
            reasons.append("التنبيه غالباً إنذار كاذب أو تشغيلي حسب قواعد الفريق، فما ترتفع أولويته.")
        else:
            if ctx.get("is_crown_jewel"):
                severity = max(_bump(severity, 1), "high", key=LEVELS.index)
                reasons.append(f"الجهاز {self.shadow.assets[alert['host']]['label']} أصل حرج بنفسه، فارتفعت الخطورة.")
            elif ctx.get("on_attack_path"):
                hops = ctx["hops_to_crown_jewel"]
                crown = self.shadow.assets[ctx["nearest_crown_jewel"]]["label"]
                if hops is not None and hops <= esc["near_hops"]:
                    severity = _bump(severity, 1)
                    reasons.append(f"الجهاز على مسار هجوم، وعلى بُعد {hops} خطوة فقط من {crown}، فارتفعت الخطورة درجة.")
                else:
                    reasons.append(f"الجهاز على مسار هجوم، لكنه بعيد عن {crown} ({hops} خطوات)، فما تغيّرت الخطورة.")
            bad_ips = [f for f in intel if f["malicious"]]
            if bad_ips:
                severity = _bump(severity, 1)
                reasons.append(f"العنوان {bad_ips[0]['ip']} مصنف مشبوه: {bad_ips[0]['note']}.")
            cap = rule.get("max_severity")
            if cap and LEVELS.index(severity) > LEVELS.index(cap):
                severity = cap
                reasons.append(f"قواعد الفريق تحدد سقف هذا النوع من التنبيهات عند {LEVELS_AR[cap]}.")

        techniques = [
            {"id": t, "name_en": self.mitre.get(t, {}).get("en", ""), "name_ar": self.mitre.get(t, {}).get("ar", ""),
             "tactic": self.mitre.get(t, {}).get("tactic", "")}
            for t in rule.get("mitre", [])
        ]
        recs = self._alert_recommendations(alert, severity, ctx)

        result = {
            "alert_id": alert["id"],
            "timestamp": alert["timestamp"],
            "host": alert.get("host", ""),
            "host_label": self.shadow.assets.get(alert.get("host", ""), {}).get("label", alert.get("host", "")),
            "user": alert.get("user", ""),
            "rule_name": alert.get("rule_name", ""),
            "title_ar": rule.get("title_ar", alert.get("rule_name", "")),
            "source_type": alert.get("source_type", "siem"),
            "phase": alert.get("phase", ""),
            "event_count": alert.get("event_count"),
            "exception_id": exception["id"] if exception else None,
            "duplicate_of": None,
            "duplicates": 0,
            "category": rule.get("category", ""),
            "base_severity": base,
            "severity": severity,
            "escalated": LEVELS.index(severity) > LEVELS.index(base),
            "likely_false_positive": fp,
            "on_attack_path": bool(ctx.get("on_attack_path")),
            "hops_to_crown_jewel": ctx.get("hops_to_crown_jewel"),
            "nearest_crown_jewel": ctx.get("nearest_crown_jewel"),
            "mitre": techniques,
            "intel": intel,
            "reasons_ar": reasons,
            "recommendations_ar": recs,
            "evidence": {"raw_log": alert.get("raw_log", ""), "src_ip": alert.get("src_ip", ""), "dest_ip": alert.get("dest_ip", "")},
        }
        fallback = self._template_explanation(result)
        if use_llm:
            text, source = llm_client.generate(self._explain_prompt(result), fallback)
        else:
            text, source = fallback, "template"
        result["explanation_ar"] = text
        result["explanation_source"] = source
        return result

    def _match_exception(self, alert: dict) -> dict | None:
        """قائمة الاستثناءات: نشاط يشبه الهجوم لكنه معروف ومصرّح."""
        for ex in self.rules.get("exceptions", {}).get("items", []):
            if ex.get("rule_name") != alert.get("rule_name"):
                continue
            if any(alert.get(f) not in values for f, values in ex.get("match", {}).items()):
                continue
            raw = alert.get("raw_log", "")
            if ex.get("raw_contains") and not any(s in raw for s in ex["raw_contains"]):
                continue
            if "max_event_count" in ex:
                count = alert.get("event_count")
                if count is None or count > ex["max_event_count"]:
                    continue
            if "hours_utc" in ex:
                start, end = ex["hours_utc"]
                if not start <= _ts(alert).hour < end:
                    continue
            return ex
        return None

    def _alert_recommendations(self, alert: dict, severity: str, ctx: dict) -> list[str]:
        recs: list[str] = []
        host = alert.get("host", "")
        if severity == "critical":
            recs.append(f"اعزل الجهاز {host} عن الشبكة فوراً وابدأ إجراءات الاستجابة للحادثة.")
        elif severity == "high":
            recs.append(f"افحص الجهاز {host} الآن وراجع السجلات المرتبطة خلال آخر ساعة.")
        if alert.get("user"):
            if severity in ("high", "critical"):
                recs.append(f"أوقف جلسات المستخدم {alert['user']} وغيّر كلمة مروره.")
        for e in self.shadow.edge_index.values():
            if e["from"] == host and e["id"] not in self.shadow.fixed_edges and ctx.get("on_attack_path"):
                recs.append(f"اقطع الخطوة التالية للمهاجم من هذا الجهاز: {e['fix']}.")
        return recs[:4]

    @staticmethod
    def _template_explanation(r: dict) -> str:
        parts = [f"التنبيه \"{r['title_ar']}\" ({r['rule_name']}) على {r['host_label']} ضمن فئة {r['category']}."]
        parts.append(f"الخطورة الأساسية {LEVELS_AR[r['base_severity']]}، والخطورة النهائية {LEVELS_AR[r['severity']]}.")
        parts.extend(r["reasons_ar"])
        if r["mitre"]:
            names = "، ".join(f"{t['name_ar']} ({t['id']})" for t in r["mitre"] if t["name_ar"])
            if names:
                parts.append(f"التقنيات المرتبطة: {names}.")
        return " ".join(parts)

    @staticmethod
    def _explain_prompt(r: dict) -> str:
        facts = {k: r[k] for k in ("rule_name", "host_label", "user", "category", "base_severity", "severity",
                                   "on_attack_path", "hops_to_crown_jewel", "reasons_ar", "evidence")}
        facts["mitre"] = [f"{t['id']} {t['name_ar']}" for t in r["mitre"]]
        return (
            "اشرح هذا التنبيه الأمني لمحلل SOC في 3 إلى 4 جمل: ماذا حدث، ولماذا هذه الخطورة، وما أهم شيء يفحصه الآن.\n"
            f"الحقائق:\n{json.dumps(facts, ensure_ascii=False, indent=1)}"
        )

    # ---------- كل التنبيهات ----------
    def _duplicates(self, alerts: list[dict]) -> dict[str, str]:
        """نفس القاعدة على نفس الجهاز خلال نافذة زمنية قصيرة = تكرار. يرجّع {رقم المكرر: رقم الأصل}."""
        window = self.rules.get("deduplication", {}).get("window_minutes", 10) * 60
        dup_of: dict[str, str] = {}
        last_original: dict[tuple, dict] = {}
        for a in sorted(alerts, key=_ts):
            key = (a.get("rule_name"), a.get("host"))
            orig = last_original.get(key)
            if orig and (_ts(a) - _ts(orig)).total_seconds() <= window:
                dup_of[a["id"]] = orig["id"]
            else:
                last_original[key] = a
        return dup_of

    def analyze_all(self, alerts: list[dict]) -> list[dict]:
        by_id = {a["id"]: a for a in alerts}
        results = {a["id"]: self.analyze_alert(a) for a in alerts}
        for dup, orig in self._duplicates(alerts).items():
            results[dup]["duplicate_of"] = orig
            results[orig]["duplicates"] += 1
        for inc in self.incidents(alerts):
            for step in inc["timeline"]:
                r = results[step["alert_id"]]
                r["incident_id"] = inc["id"]
                if inc.get("escalated_by_correlation") and r["severity"] != "critical":
                    r["severity"] = "critical"
                    r["escalated"] = True
                    r["reasons_ar"].append(
                        f"التنبيه جزء من حادثة {inc['id']} ({_count(inc['alert_count'], 'تنبيه واحد', 'تنبيهين', 'تنبيهات', 'تنبيهاً')}) تتبع مسار هجوم معروف، فصار حرج."
                    )
                    r["explanation_ar"] = self._template_explanation(r)
                    alert = by_id[r["alert_id"]]
                    r["recommendations_ar"] = self._alert_recommendations(
                        alert, "critical", self.shadow.host_context(alert.get("host", ""))
                    )
        # المكرر ياخذ نفس نتيجة الأصل
        for r in results.values():
            if r["duplicate_of"]:
                orig = results[r["duplicate_of"]]
                r["severity"], r["incident_id"] = orig["severity"], orig.get("incident_id")
                r["escalated"] = LEVELS.index(r["severity"]) > LEVELS.index(r["base_severity"])
        out = list(results.values())
        out.sort(key=lambda r: (-LEVELS.index(r["severity"]), r["likely_false_positive"], r["timestamp"]))
        return out

    # ---------- جمع التنبيهات في حوادث (قصة الهجوم) ----------
    def incidents(self, alerts: list[dict], use_llm: bool = False) -> list[dict]:
        analyzed = {r["alert_id"]: r for r in (self.analyze_alert(a) for a in alerts)}
        dup_of = self._duplicates(alerts)
        dup_count: dict[str, int] = {}
        for orig in dup_of.values():
            dup_count[orig] = dup_count.get(orig, 0) + 1
        candidates = [a for a in alerts if not analyzed[a["id"]]["likely_false_positive"] and a["id"] not in dup_of]
        window = self.rules["correlation"]["window_minutes"] * 60
        g = self.shadow.graph(set())

        parent = {a["id"]: a["id"] for a in candidates}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for i, a in enumerate(candidates):
            for b in candidates[i + 1:]:
                if abs((_ts(a) - _ts(b)).total_seconds()) > window:
                    continue
                ha, hb = a.get("host"), b.get("host")
                linked = ha == hb or g.has_edge(ha, hb) or g.has_edge(hb, ha)
                if linked:
                    parent[find(a["id"])] = find(b["id"])

        groups: dict[str, list[dict]] = {}
        for a in candidates:
            groups.setdefault(find(a["id"]), []).append(a)

        incidents = []
        for members in groups.values():
            members.sort(key=_ts)
            rs = [analyzed[m["id"]] for m in members]
            severity = max((r["severity"] for r in rs), key=LEVELS.index)
            hosts = list(dict.fromkeys(r["host"] for r in rs))
            matched = self._match_path(hosts)
            by_correlation = bool(matched) and len(members) >= self.rules["correlation"]["min_alerts_for_critical"]
            if by_correlation:
                severity = "critical"
            incident = {
                "escalated_by_correlation": by_correlation,
                "severity": severity,
                "start": members[0]["timestamp"],
                "end": members[-1]["timestamp"],
                "alert_count": len(members),
                "hosts": hosts,
                "users": sorted({r["user"] for r in rs if r["user"]}),
                "mitre": sorted({t["id"] for r in rs for t in r["mitre"]}),
                "timeline": [
                    {"time": r["timestamp"], "host": r["host"], "host_label": r["host_label"], "rule_name": r["rule_name"],
                     "title_ar": r["title_ar"], "phase": r["phase"], "phase_ar": PHASES_AR.get(r["phase"], r["phase"]),
                     "source_type": r["source_type"],
                     "category": r["category"], "severity": "critical" if by_correlation else r["severity"],
                     "alert_id": r["alert_id"], "repeats": dup_count.get(r["alert_id"], 0)}
                    for r in rs
                ],
                "matched_attack_path": matched,
            }
            incident["five_w"] = self._five_w(incident, rs, members)
            incident["summary_ar"], incident["summary_source"] = self._incident_summary(incident, use_llm)
            incidents.append(incident)

        incidents.sort(key=lambda i: (-LEVELS.index(i["severity"]), -i["alert_count"]))
        for n, inc in enumerate(incidents, 1):
            inc["id"] = f"INC-{n:03d}"
        return incidents

    def _five_w(self, inc: dict, rs: list[dict], members: list[dict]) -> dict:
        """تقرير التحقيق على الأسئلة الخمسة: من؟ متى؟ كيف؟ لماذا؟ ماذا فعل؟"""
        label = lambda h: self.shadow.assets.get(h, {}).get("label", h)  # noqa: E731
        ips = list(dict.fromkeys(ip for m in members for ip in (m.get("src_ip"), m.get("dest_ip")) if ip))
        bad = [f for r in rs for f in r["intel"] if f["malicious"]]
        start, end = _ts(members[0]), _ts(members[-1])
        phases = list(dict.fromkeys(PHASES_AR.get(r["phase"], r["phase"]) or r["category"] for r in rs))
        m = inc["matched_attack_path"]

        why: list[str] = []
        if m:
            why.append(f"النشاط يمشي على مسار هجوم اكتشفه الظل الرقمي، ينتهي عند {label(m['target'])}.")
        crown_hit = [h for h in inc["hosts"] if self.shadow.assets.get(h, {}).get("crown_jewel")]
        if crown_hit:
            why.append(f"وصل النشاط لأصل حرج: {'، '.join(label(h) for h in crown_hit)}.")
        if bad:
            why.append(f"تواصل مع عناوين مشبوهة: {'، '.join(sorted({f['ip'] for f in bad}))}.")
        if inc["escalated_by_correlation"]:
            why.append(f"{_count(inc['alert_count'], 'تنبيه واحد', 'تنبيهين', 'تنبيهات', 'تنبيهاً')} مترابطة زمنياً وعلى أجهزة متصلة، فصارت حادثة حرجة.")

        return {
            "who": {
                "users": inc["users"],
                "hosts": [label(h) for h in inc["hosts"]],
                "ips": ips,
                "suspicious_ips": sorted({f["ip"] for f in bad}),
            },
            "when": {
                "start": inc["start"],
                "end": inc["end"],
                "duration_minutes": int((end - start).total_seconds() // 60),
            },
            "how": {
                "entry_vector": m["entry_vector"] if m else "",
                "phases": phases,
                "mitre": inc["mitre"],
            },
            "why": why,
            "what": [f"{label(r['host'])}: {r['title_ar']}" for r in rs],
            "next_step": m["next_expected_label"] if m else None,
        }

    def _match_path(self, hosts: list[str]) -> dict | None:
        """أقرب مسار هجوم من الظل الرقمي يمشي عليه المهاجم، والخطوة المتوقعة الجاية."""
        best, best_overlap = None, 0
        for p in self.shadow.attack_paths():
            overlap = sum(1 for h in hosts if h in p.nodes)
            if overlap > best_overlap:
                best, best_overlap = p, overlap
        if best is None or best_overlap < 2:
            return None
        furthest = max(best.nodes.index(h) for h in hosts if h in best.nodes)
        next_node = best.nodes[furthest + 1] if furthest + 1 < len(best.nodes) else None
        d = best.to_dict(self.shadow)
        d["compromised_hosts"] = [h for h in best.nodes if h in hosts]
        d["next_expected_host"] = next_node
        d["next_expected_label"] = self.shadow.assets[next_node]["label"] if next_node else None
        return d

    def _incident_summary(self, inc: dict, use_llm: bool) -> tuple[str, str]:
        labels = [self.shadow.assets.get(h, {}).get("label", h) for h in inc["hosts"]]
        text = (
            f"حادثة بخطورة {LEVELS_AR[inc['severity']]} تضم {_count(inc['alert_count'], 'تنبيه واحد', 'تنبيهين', 'تنبيهات', 'تنبيهاً')} على "
            f"{_count(len(labels), 'جهاز واحد', 'جهازين', 'أجهزة', 'جهازاً')}: {'، '.join(labels)}."
        )
        m = inc["matched_attack_path"]
        if m:
            text += f" النشاط يتبع مسار هجوم اكتشفه الظل الرقمي مسبقاً يبدأ من {m['entry_vector']} وينتهي عند {self.shadow.assets[m['target']]['label']}."
            if m["next_expected_label"]:
                text += f" الخطوة المتوقعة الجاية للمهاجم: {m['next_expected_label']}، فاحمِه الآن."
            else:
                text += " المهاجم وصل للأصل الحرج، والأولوية الآن احتواء الحادثة ومنع تسريب البيانات."
        if not use_llm:
            return text, "template"
        facts = json.dumps({k: inc[k] for k in ("severity", "hosts", "users", "mitre", "timeline", "matched_attack_path")},
                           ensure_ascii=False, indent=1)
        prompt = INCIDENT_PROMPT.format(facts=facts)
        return llm_client.generate(prompt, text, max_tokens=500)
