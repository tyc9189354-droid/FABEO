#!/usr/bin/env python3
"""
================================================================================
FABEO: Benchmark Exporter (JSON & CSV)
================================================================================
"""

import os
import json
import csv
from typing import List, Dict, Any
from ..core.metrics import SchemeMetrics


class BenchmarkExporter:
    @staticmethod
    def export_to_json(metrics: List[SchemeMetrics], file_path: str):
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        data = [m.to_dict() if isinstance(m, SchemeMetrics) else m for m in metrics]
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    @staticmethod
    def export_to_csv(metrics: List[SchemeMetrics], file_path: str):
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        if not metrics:
            return

        flat_data = []
        for m in metrics:
            d = m.to_dict() if isinstance(m, SchemeMetrics) else dict(m)
            # Flatten group ops
            for phase in ["keygen", "enc", "dec"]:
                ops_key = f"group_ops_{phase}"
                if ops_key in d and isinstance(d[ops_key], dict):
                    for op_name, count in d[ops_key].items():
                        d[f"{phase}_{op_name}"] = count
                    del d[ops_key]
            flat_data.append(d)

        fieldnames = list(flat_data[0].keys())
        with open(file_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(flat_data)
