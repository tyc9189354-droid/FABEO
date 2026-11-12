#!/usr/bin/env python3
"""
================================================================================
FABEO: Performance Plotter & Table Formatter
Generates ASCII comparison tables replicating Paper Figure 3 and Tables 3, 5
================================================================================
"""

from typing import List, Dict, Any
from ..core.metrics import SchemeMetrics


class BenchmarkPlotter:
    @staticmethod
    def print_summary_table(metrics: List[SchemeMetrics]):
        print("\n" + "=" * 90)
        print(f"{'Scheme':<12} | {'Attrs':<6} | {'KeyGen(ms)':<11} | {'Enc(ms)':<10} | {'Dec(ms)':<10} | {'Pairings':<9} | {'SK Size':<8} | {'CT Size':<8}")
        print("-" * 90)

        for m in metrics:
            pairings = m.group_ops_dec.get("pairings", 0)
            sk_size = f"{m.sk_g1_elements}G1+{m.sk_g2_elements}G2"
            ct_size = f"{m.ct_g1_elements}G1+{m.ct_g2_elements}G2"

            print(
                f"{m.scheme_name:<12} | "
                f"{m.num_attributes:<6} | "
                f"{m.keygen_time_ms:<11.2f} | "
                f"{m.enc_time_ms:<10.2f} | "
                f"{m.dec_time_ms:<10.2f} | "
                f"{pairings:<9} | "
                f"{sk_size:<8} | "
                f"{ct_size:<8}"
            )
        print("=" * 90 + "\n")

    @staticmethod
    def print_speedup_analysis(metrics: List[SchemeMetrics]):
        """Prints relative speedup and size reduction of FABEO over baselines."""
        grouped: Dict[int, Dict[str, SchemeMetrics]] = {}
        for m in metrics:
            grouped.setdefault(m.num_attributes, {})[m.scheme_name] = m

        print("\n" + "=" * 90)
        print("FABEO Efficiency Improvement Analysis (Decryption Speedup & Size Savings)")
        print("=" * 90)
        for n, sch_dict in sorted(grouped.items()):
            if "FABEO_CP" in sch_dict:
                f = sch_dict["FABEO_CP"]
                print(f"\n[Attribute Count N = {n}]")
                for other_name, other_m in sch_dict.items():
                    if other_name == "FABEO_CP":
                        continue
                    speedup = other_m.dec_time_ms / max(f.dec_time_ms, 0.0001)
                    p_fabeo = f.group_ops_dec.get("pairings", 0)
                    p_other = other_m.group_ops_dec.get("pairings", 0)
                    print(
                        f"  vs {other_name:<10}: Decryption is {speedup:.1f}x faster "
                        f"({p_fabeo} pairings vs {p_other} pairings)"
                    )
        print("=" * 90 + "\n")
