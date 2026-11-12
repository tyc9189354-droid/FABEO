#!/usr/bin/env python3
"""
================================================================================
FABEO: Metrics and Profiler
================================================================================
"""

import time
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict


@dataclass
class SchemeMetrics:
    scheme_name: str
    num_attributes: int
    policy_str: str
    tau: int
    setup_time_ms: float
    keygen_time_ms: float
    enc_time_ms: float
    dec_time_ms: float
    sk_g1_elements: int
    sk_g2_elements: int
    ct_g1_elements: int
    ct_g2_elements: int
    ct_gt_elements: int
    group_ops_keygen: Dict[str, int]
    group_ops_enc: Dict[str, int]
    group_ops_dec: Dict[str, int]
    correctness: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class Timer:
    """High precision nanosecond stopwatch."""
    def __enter__(self):
        self.start = time.perf_counter_ns()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end = time.perf_counter_ns()
        self.elapsed_ms = (self.end - self.start) / 1_000_000.0
