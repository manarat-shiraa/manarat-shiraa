"""الظل الرقمي: نسخة افتراضية من الشبكة كـ Graph موجّه، وتحليل مسارات الهجوم.

المفاهيم:
- كل حافة (edge) خطوة ممكنة للمهاجم، وصعوبتها difficulty بين 0 و 1.
- احتمال نجاح الخطوة = 1 - difficulty، واحتمال نجاح المسار = حاصل ضرب احتمالات خطواته.
- خطر كل أصل حرج = أعلى احتمال وصول له × أهميته (criticality).
- مؤشر الخطر الكلي (0-100) = مجموع خطر الأصول الحرجة ÷ مجموع أهميتها × 100.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import reduce
from pathlib import Path

import networkx as nx

MAX_PATH_LEN = 8


@dataclass
class AttackPath:
    nodes: list[str]
    edges: list[str]
    probability: float
    entry: str
    target: str

    def to_dict(self, shadow: "DigitalShadow") -> dict:
        return {
            "nodes": self.nodes,
            "edges": self.edges,
            "probability": round(self.probability, 4),
            "hops": len(self.edges),
            "entry": self.entry,
            "entry_vector": shadow.entry_vectors.get(self.entry, {}).get("vector", ""),
            "target": self.target,
            "steps": [
                {
                    "edge_id": eid,
                    "from": shadow.edge_index[eid]["from"],
                    "to": shadow.edge_index[eid]["to"],
                    "label": shadow.edge_index[eid]["label"],
                    "mitre": shadow.edge_index[eid].get("mitre", ""),
                }
                for eid in self.edges
            ],
        }


@dataclass
class DigitalShadow:
    network: dict
    fixed_edges: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.assets = {a["id"]: a for a in self.network["assets"]}
        self.edge_index = {e["id"]: e for e in self.network["edges"]}
        self.entry_vectors = {e["asset"]: e for e in self.network["entry_points"]}
        self.crown_jewels = [a["id"] for a in self.network["assets"] if a.get("crown_jewel")]

    # ---------- بناء الـ Graph ----------
    @classmethod
    def from_file(cls, path: Path) -> "DigitalShadow":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def graph(self, fixed: set[str] | None = None) -> nx.DiGraph:
        fixed = self.fixed_edges if fixed is None else fixed
        g = nx.DiGraph()
        for aid, asset in self.assets.items():
            g.add_node(aid, **asset)
        for eid, e in self.edge_index.items():
            if eid in fixed:
                continue
            g.add_edge(e["from"], e["to"], id=eid, p=1.0 - float(e["difficulty"]))
        return g

    # ---------- المسارات ----------
    def attack_paths(self, fixed: set[str] | None = None) -> list[AttackPath]:
        g = self.graph(fixed)
        paths: list[AttackPath] = []
        for entry in self.entry_vectors:
            for target in self.crown_jewels:
                if entry == target or entry not in g or target not in g:
                    continue
                for nodes in nx.all_simple_paths(g, entry, target, cutoff=MAX_PATH_LEN):
                    edge_ids = [g.edges[u, v]["id"] for u, v in zip(nodes, nodes[1:])]
                    prob = reduce(lambda acc, uv: acc * g.edges[uv]["p"], zip(nodes, nodes[1:]), 1.0)
                    paths.append(AttackPath(nodes, edge_ids, prob, entry, target))
        paths.sort(key=lambda p: (-p.probability, len(p.edges)))
        return paths

    def risk_score(self, fixed: set[str] | None = None) -> float:
        paths = self.attack_paths(fixed)
        total_weight = sum(self.assets[c]["criticality"] for c in self.crown_jewels) or 1
        raw = 0.0
        for crown in self.crown_jewels:
            best = max((p.probability for p in paths if p.target == crown), default=0.0)
            raw += best * self.assets[crown]["criticality"]
        return round(100 * raw / total_weight, 1)

    # ---------- نقاط الاختناق والتوصيات ----------
    def min_cut_edges(self, fixed: set[str] | None = None) -> list[str]:
        """أقل عدد من الحواف اللي إصلاحها يقطع كل الطرق من نقاط الدخول للأصول الحرجة."""
        g = self.graph(fixed).copy()
        nx.set_edge_attributes(g, 1, "cap")
        src, dst = "__SRC__", "__DST__"
        # الحواف الوهمية ما تنقطع (سعتها كبيرة)، فالقطع يقع على حواف الشبكة الحقيقية فقط
        for entry in self.entry_vectors:
            g.add_edge(src, entry, cap=10_000)
        for crown in self.crown_jewels:
            g.add_edge(crown, dst, cap=10_000)
        if not nx.has_path(g, src, dst):
            return []
        _, (reach, _) = nx.minimum_cut(g, src, dst, capacity="cap")
        ids = [
            g.edges[u, v]["id"]
            for u in reach
            for v in g.successors(u)
            if v not in reach and "id" in g.edges[u, v]
        ]
        return sorted(ids)

    def recommendations(self, fixed: set[str] | None = None, top: int = 5) -> list[dict]:
        """ترتيب الإصلاحات حسب كم تنقّص الخطر لو انطبقت لحالها."""
        fixed = set(self.fixed_edges if fixed is None else fixed)
        base = self.risk_score(fixed)
        paths = self.attack_paths(fixed)
        used = {eid for p in paths for eid in p.edges}
        recs = []
        for eid in used:
            after = self.risk_score(fixed | {eid})
            e = self.edge_index[eid]
            recs.append(
                {
                    "edge_id": eid,
                    "from": e["from"],
                    "to": e["to"],
                    "issue": e["label"],
                    "fix": e.get("fix", ""),
                    "mitre": e.get("mitre", ""),
                    "paths_blocked": sum(1 for p in paths if eid in p.edges),
                    "risk_after": after,
                    "risk_reduction_pct": round(100 * (base - after) / base, 1) if base else 0.0,
                }
            )
        recs.sort(key=lambda r: (-r["risk_reduction_pct"], -r["paths_blocked"]))
        return recs[:top]

    # ---------- سياق جهاز معيّن (يستخدمه مرصاد) ----------
    def host_context(self, host: str, fixed: set[str] | None = None) -> dict:
        if host not in self.assets:
            return {"known": False, "on_attack_path": False, "hops_to_crown_jewel": None, "nearest_crown_jewel": None}
        asset = self.assets[host]
        if asset.get("crown_jewel"):
            return {
                "known": True,
                "on_attack_path": True,
                "is_crown_jewel": True,
                "hops_to_crown_jewel": 0,
                "nearest_crown_jewel": host,
                "criticality": asset["criticality"],
            }
        paths = self.attack_paths(fixed)
        on_path = any(host in p.nodes for p in paths)
        g = self.graph(fixed)
        best_hops, nearest = None, None
        for crown in self.crown_jewels:
            if nx.has_path(g, host, crown):
                hops = nx.shortest_path_length(g, host, crown)
                if best_hops is None or hops < best_hops:
                    best_hops, nearest = hops, crown
        return {
            "known": True,
            "on_attack_path": on_path,
            "is_crown_jewel": False,
            "hops_to_crown_jewel": best_hops if on_path else None,
            "nearest_crown_jewel": nearest if on_path else None,
            "criticality": asset["criticality"],
        }

    # ---------- ملخص كامل للواجهة ----------
    def analysis(self, fixed: set[str] | None = None, top_paths: int = 10) -> dict:
        fixed = set(self.fixed_edges if fixed is None else fixed)
        paths = self.attack_paths(fixed)
        baseline = self.risk_score(set())
        current = self.risk_score(fixed)
        return {
            "risk_baseline": baseline,
            "risk_current": current,
            "risk_reduction_pct": round(100 * (baseline - current) / baseline, 1) if baseline else 0.0,
            "paths_total": len(paths),
            "paths": [p.to_dict(self) for p in paths[:top_paths]],
            "nodes_on_paths": sorted({n for p in paths for n in p.nodes}),
            "edges_on_paths": sorted({e for p in paths for e in p.edges}),
            "min_cut_edges": self.min_cut_edges(fixed),
            "recommendations": self.recommendations(fixed),
            "fixed_edges": sorted(fixed),
        }
