"""
Aegis AI — Risk Propagation Model
Propagates risk scores through the attack graph using a BFS-style
belief-propagation algorithm.

Core idea:
  Every node starts with its own intrinsic risk.
  Risk is then propagated along edges, discounted by each edge's
  probability, so downstream nodes accumulate *propagated* risk
  from all upstream paths.

This answers: "If the attacker starts at the entry point, how much
accumulated risk reaches each impact node?"
"""
from __future__ import annotations

from typing import Dict, List, Tuple
from collections import deque

import networkx as nx


class RiskPropagationEngine:
    """
    Runs forward risk propagation on an attack graph.

    Algorithm (simplified loopy belief propagation):
      1. Seed the attacker node with risk = 1.0 (certainty of presence).
      2. BFS outward. For each edge u→v with probability p:
            propagated_risk[v] = max(propagated_risk[v],
                                     propagated_risk[u] × p × severity_factor(v))
      3. Iterate until convergence or max_iterations.
    """

    def __init__(self, graph: nx.DiGraph, max_iterations: int = 10):
        self.graph = graph
        self.max_iterations = max_iterations
        self.propagated_risk: Dict[str, float] = {}
        self._converged = False

    def propagate(self) -> Dict[str, float]:
        """
        Run propagation and return {node_id: propagated_risk}.
        """
        g = self.graph

        # Initialize propagated risk
        for node in g.nodes:
            self.propagated_risk[node] = 0.0

        # Seed: attacker starts with full certainty
        if "attacker" in g.nodes:
            self.propagated_risk["attacker"] = 1.0
        else:
            # Fallback: seed all nodes with no incoming edges
            for node in g.nodes:
                if g.in_degree(node) == 0:
                    self.propagated_risk[node] = 1.0

        # Iterate
        for _iteration in range(self.max_iterations):
            changed = False
            # Process nodes in topological-ish order (BFS from sources)
            for u, v, data in g.edges(data=True):
                prob = data.get("probability", 0.5)
                node_risk = g.nodes[v].get("risk", 1.0) / 10.0  # normalize 0-1
                new_risk = self.propagated_risk[u] * prob * max(node_risk, 0.1)
                if new_risk > self.propagated_risk[v]:
                    self.propagated_risk[v] = new_risk
                    changed = True

            if not changed:
                self._converged = True
                break

        return self.propagated_risk

    def get_risk_ranked_nodes(self) -> List[Tuple[str, float, Dict]]:
        """
        Return all nodes sorted by propagated risk descending.
        Each entry: (node_id, propagated_risk, node_data)
        """
        if not self.propagated_risk:
            self.propagate()

        ranked = []
        for nid, risk in self.propagated_risk.items():
            data = dict(self.graph.nodes[nid])
            data["propagated_risk"] = round(risk, 4)
            ranked.append((nid, round(risk, 4), data))

        ranked.sort(key=lambda x: x[1], reverse=True)
        return ranked

    def get_critical_nodes(self, threshold: float = 0.3) -> List[Dict]:
        """
        Return nodes whose propagated risk exceeds the threshold.
        """
        ranked = self.get_risk_ranked_nodes()
        return [
            {
                "id": nid,
                "label": data.get("label", nid),
                "type": data.get("node_type", "unknown"),
                "intrinsic_risk": data.get("risk", 0.0),
                "propagated_risk": risk,
            }
            for nid, risk, data in ranked
            if risk >= threshold
        ]

    def to_dict(self) -> Dict:
        """
        Serialize propagation results for the API.
        """
        if not self.propagated_risk:
            self.propagate()

        critical = self.get_critical_nodes()
        all_risks = self.get_risk_ranked_nodes()

        # Impact nodes with propagated risk
        impact_risks = [
            {
                "id": nid,
                "label": data.get("label", nid),
                "propagated_risk": risk,
                "description": data.get("description", ""),
            }
            for nid, risk, data in all_risks
            if data.get("node_type") == "impact" and risk > 0.0
        ]

        max_risk = max((r for _, r, _ in all_risks), default=0.0)

        return {
            "converged": self._converged,
            "max_propagated_risk": round(max_risk, 4),
            "critical_nodes": critical,
            "impact_risks": impact_risks,
            "all_node_risks": {
                nid: round(risk, 4)
                for nid, risk, _ in all_risks
                if risk > 0.0
            },
        }
