#!/usr/bin/env python3
"""
================================================================================
FABEO: Benchmark Runner
Replicates experiments in Section 7 (Figure 3 & Tables 3-6)
================================================================================
"""

import time
from typing import List, Dict, Any, Set
from ..core.pairing_group import PairingGroup
from ..core.msp import MSP
from ..core.dfa import DFA
from ..core.metrics import SchemeMetrics, Timer
from ..schemes.fabeo_cp import FabeoCP
from ..schemes.fabeo_kp import FabeoKP
from ..schemes.fabeo_dfa import FabeoDFA
from ..schemes.abgw_cp import AbgwCP
from ..schemes.abgw_kp import AbgwKP
from ..schemes.bsw_cp import BswCP


class BenchmarkRunner:
    """Executes comparative benchmarks across attribute sizes and schemes."""

    def __init__(self, curve_name: str = "BLS12-381"):
        self.group = PairingGroup(curve_name=curve_name)

    def run_cp_benchmark(
        self,
        attribute_counts: List[int] = [10, 20, 50, 100],
        schemes: List[str] = ["FABEO_CP", "ABGW_CP", "BSW_CP"],
        trials: int = 5,
    ) -> List[SchemeMetrics]:
        results = []

        for N in attribute_counts:
            # Policy: Attr1 and Attr2 and ... and AttrN
            attrs = [f"ATTR_{i}" for i in range(1, N + 1)]
            policy_str = " AND ".join(attrs)
            attr_set = set(attrs)

            for s_name in schemes:
                if s_name == "FABEO_CP":
                    scheme = FabeoCP(self.group)
                elif s_name == "ABGW_CP":
                    scheme = AbgwCP(self.group)
                elif s_name == "BSW_CP":
                    scheme = BswCP(self.group)
                else:
                    continue

                # Measure Setup
                setup_times = []
                for _ in range(trials):
                    with Timer() as t:
                        mpk, msk = scheme.setup()
                    setup_times.append(t.elapsed_ms)
                setup_ms = sum(setup_times) / trials

                # Measure KeyGen
                self.group.profiler.reset()
                keygen_times = []
                for _ in range(trials):
                    with Timer() as t:
                        sk = scheme.keygen(msk, attr_set)
                    keygen_times.append(t.elapsed_ms)
                keygen_ms = sum(keygen_times) / trials
                ops_keygen = self.group.profiler.snapshot()

                # Measure Encrypt
                self.group.profiler.reset()
                enc_times = []
                for _ in range(trials):
                    with Timer() as t:
                        ct, d_enc = scheme.encrypt(mpk, policy_str)
                    enc_times.append(t.elapsed_ms)
                enc_ms = sum(enc_times) / trials
                ops_enc = self.group.profiler.snapshot()

                # Measure Decrypt
                self.group.profiler.reset()
                dec_times = []
                correct = True
                for _ in range(trials):
                    with Timer() as t:
                        d_dec = scheme.decrypt(mpk, ct, sk)
                    dec_times.append(t.elapsed_ms)
                    if d_enc != d_dec:
                        correct = False
                dec_ms = sum(dec_times) / trials
                ops_dec = self.group.profiler.snapshot()

                # Calculate sizes
                if s_name == "FABEO_CP":
                    sk_g1 = 1 + len(sk["sk2"])
                    sk_g2 = 1
                    ct_g1 = len(ct["ct3"])
                    ct_g2 = 1 + len(ct["ct2"])
                    ct_gt = 1
                    tau = ct["tau"]
                elif s_name == "ABGW_CP":
                    sk_g1 = 0
                    sk_g2 = 2 + len(sk["sk3"])
                    ct_g1 = len(ct["ct1"]) + len(ct["ct2"]) + len(ct["ct3"])
                    ct_g2 = 0
                    ct_gt = 1
                    tau = 1
                elif s_name == "BSW_CP":
                    sk_g1 = 1 + len(sk["sk1"])
                    sk_g2 = len(sk["sk2"])
                    ct_g1 = len(ct["ct2"])
                    ct_g2 = 1 + len(ct["ct1"])
                    ct_gt = 1
                    tau = 1

                metric = SchemeMetrics(
                    scheme_name=s_name,
                    num_attributes=N,
                    policy_str=f"{N}-clause AND",
                    tau=tau,
                    setup_time_ms=setup_ms,
                    keygen_time_ms=keygen_ms,
                    enc_time_ms=enc_ms,
                    dec_time_ms=dec_ms,
                    sk_g1_elements=sk_g1,
                    sk_g2_elements=sk_g2,
                    ct_g1_elements=ct_g1,
                    ct_g2_elements=ct_g2,
                    ct_gt_elements=ct_gt,
                    group_ops_keygen=ops_keygen,
                    group_ops_enc=ops_enc,
                    group_ops_dec=ops_dec,
                    correctness=correct,
                )
                results.append(metric)

        return results

    def run_kp_benchmark(
        self,
        attribute_counts: List[int] = [10, 20, 50, 100],
        schemes: List[str] = ["FABEO_KP", "ABGW_KP"],
        trials: int = 5,
    ) -> List[SchemeMetrics]:
        results = []

        for N in attribute_counts:
            attrs = [f"ATTR_{i}" for i in range(1, N + 1)]
            policy_str = " AND ".join(attrs)
            attr_set = set(attrs)

            for s_name in schemes:
                if s_name == "FABEO_KP":
                    scheme = FabeoKP(self.group)
                elif s_name == "ABGW_KP":
                    scheme = AbgwKP(self.group)
                else:
                    continue

                # Setup
                setup_times = []
                for _ in range(trials):
                    with Timer() as t:
                        mpk, msk = scheme.setup()
                    setup_times.append(t.elapsed_ms)
                setup_ms = sum(setup_times) / trials

                # KeyGen
                self.group.profiler.reset()
                keygen_times = []
                for _ in range(trials):
                    with Timer() as t:
                        sk = scheme.keygen(msk, policy_str)
                    keygen_times.append(t.elapsed_ms)
                keygen_ms = sum(keygen_times) / trials
                ops_keygen = self.group.profiler.snapshot()

                # Encrypt
                self.group.profiler.reset()
                enc_times = []
                for _ in range(trials):
                    with Timer() as t:
                        ct, d_enc = scheme.encrypt(mpk, attr_set)
                    enc_times.append(t.elapsed_ms)
                enc_ms = sum(enc_times) / trials
                ops_enc = self.group.profiler.snapshot()

                # Decrypt
                self.group.profiler.reset()
                dec_times = []
                correct = True
                for _ in range(trials):
                    with Timer() as t:
                        d_dec = scheme.decrypt(mpk, ct, sk)
                    dec_times.append(t.elapsed_ms)
                    if d_enc != d_dec:
                        correct = False
                dec_ms = sum(dec_times) / trials
                ops_dec = self.group.profiler.snapshot()

                if s_name == "FABEO_KP":
                    sk_g1 = len(sk["sk2"])
                    sk_g2 = len(sk["sk1"])
                    ct_g1 = len(ct["ct1"])
                    ct_g2 = 1
                    ct_gt = 1
                    tau = sk["tau"]
                else:
                    sk_g1 = 0
                    sk_g2 = len(sk["sk1"]) + len(sk["sk2"])
                    ct_g1 = len(ct["ct1"]) + len(ct["ct2"])
                    ct_g2 = 0
                    ct_gt = 1
                    tau = 1

                metric = SchemeMetrics(
                    scheme_name=s_name,
                    num_attributes=N,
                    policy_str=f"{N}-clause AND",
                    tau=tau,
                    setup_time_ms=setup_ms,
                    keygen_time_ms=keygen_ms,
                    enc_time_ms=enc_ms,
                    dec_time_ms=dec_ms,
                    sk_g1_elements=sk_g1,
                    sk_g2_elements=sk_g2,
                    ct_g1_elements=ct_g1,
                    ct_g2_elements=ct_g2,
                    ct_gt_elements=ct_gt,
                    group_ops_keygen=ops_keygen,
                    group_ops_enc=ops_enc,
                    group_ops_dec=ops_dec,
                    correctness=correct,
                )
                results.append(metric)

        return results

    def run_dfa_benchmark(
        self,
        string_lengths: List[int] = [10, 20, 50, 100],
        trials: int = 5,
    ) -> List[Dict[str, Any]]:
        results = []
        scheme = FabeoDFA(self.group)
        alphabet = {"0", "1"}
        dfa = DFA.from_pattern_substring("101", alphabet)

        for l in string_lengths:
            # String ending in 101
            x = ["0"] * (l - 3) + ["1", "0", "1"]

            # Setup
            with Timer() as t:
                mpk, msk = scheme.setup(alphabet)
            setup_ms = t.elapsed_ms

            # KeyGen
            with Timer() as t:
                sk = scheme.keygen(msk, dfa)
            keygen_ms = t.elapsed_ms

            # Encrypt
            self.group.profiler.reset()
            with Timer() as t:
                ct, d_enc = scheme.encrypt(mpk, x)
            enc_ms = t.elapsed_ms

            # Decrypt
            self.group.profiler.reset()
            with Timer() as t:
                d_dec = scheme.decrypt(mpk, ct, sk)
            dec_ms = t.elapsed_ms

            ops_dec = self.group.profiler.snapshot()
            correct = (d_enc == d_dec)

            results.append({
                "scheme_name": "FABEO_DFA",
                "string_length": l,
                "setup_time_ms": setup_ms,
                "keygen_time_ms": keygen_ms,
                "enc_time_ms": enc_ms,
                "dec_time_ms": dec_ms,
                "pairings_dec": ops_dec.get("pairings", 0),
                "correctness": correct,
            })

        return results
