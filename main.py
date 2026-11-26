#!/usr/bin/env python3
"""
================================================================================
FABEO: Fast Attribute-Based Encryption with Optimal Security
Main CLI Entrypoint
Reference: Doreen Riepel & Hoeteck Wee (CCS / ePrint 2022)
================================================================================
"""

import sys
import os
import argparse
from typing import List

# Ensure parent directory and current directory are in sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(SCRIPT_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

# Ensure FABEO package resolves properly in standalone execution
if "FABEO" not in sys.modules:
    import types
    pkg = types.ModuleType("FABEO")
    pkg.__path__ = [SCRIPT_DIR]
    pkg.__file__ = os.path.join(SCRIPT_DIR, "__init__.py")
    sys.modules["FABEO"] = pkg

from FABEO.core.pairing_group import PairingGroup
from FABEO.core.msp import MSP, PolicyParser
from FABEO.core.dfa import DFA
from FABEO.tool import FabeoTool
from FABEO.runner.benchmark_runner import BenchmarkRunner
from FABEO.analysis.exporter import BenchmarkExporter
from FABEO.analysis.plotter import BenchmarkPlotter


def cmd_demo(args):
    print("=" * 80)
    print("           FABEO: Fast Attribute-Based Encryption with Optimal Security")
    print("               Demonstration: CP-ABE, KP-ABE, and DFA Schemes")
    print("=" * 80)

    tool = FabeoTool()

    # 1. CP-ABE Demonstration
    print("\n--- [1] Ciphertext-Policy ABE (CP-ABE) ---")
    mpk_cp, msk_cp = tool.cp_setup()
    policy = "(MEDICINE:DOCTOR AND DEPT:CARDIOLOGY) OR ROLE:CHIEF_OF_MEDICINE"
    print(f"Access Policy: {policy}")

    # Patient record
    patient_data = b"CONFIDENTIAL MEDICAL RECORD: Patient #4092 - Normal ECG, Troponin I normal."
    pkg_cp = tool.cp_encrypt_message(mpk_cp, policy, patient_data)
    print(f"Encrypted message size: {len(pkg_cp['dem_payload']['ciphertext'])} hex chars")

    # Key 1: Satisfying (Doctor in Cardiology)
    sk1 = tool.cp_keygen(msk_cp, {"MEDICINE:DOCTOR", "DEPT:CARDIOLOGY"})
    dec1 = tool.cp_decrypt_message(mpk_cp, pkg_cp, sk1)
    print(f"[Authorized Key 1] Decrypted: {dec1.decode()}")

    # Key 2: Non-satisfying (Nurse in Cardiology)
    sk2 = tool.cp_keygen(msk_cp, {"MEDICINE:NURSE", "DEPT:CARDIOLOGY"})
    try:
        tool.cp_decrypt_message(mpk_cp, pkg_cp, sk2)
        print("ERROR: Unauthorized key decrypted!")
    except ValueError as e:
        print(f"[Unauthorized Key 2] Correctly rejected: {e}")

    # 2. Multi-Use Attribute CP-ABE Demonstration
    print("\n--- [2] CP-ABE Multi-Use Attributes (tau > 1) ---")
    multi_policy = "(ATTR_A AND ATTR_B) OR (ATTR_A AND ATTR_C)"
    print(f"Policy with attribute reuse: {multi_policy}")
    pkg_multi = tool.cp_encrypt_message(mpk_cp, multi_policy, b"Shared sensitive payload")
    sk_multi = tool.cp_keygen(msk_cp, {"ATTR_A", "ATTR_C"})
    dec_multi = tool.cp_decrypt_message(mpk_cp, pkg_multi, sk_multi)
    print(f"Decrypted successfully with multi-use key: {dec_multi.decode()}")

    # 3. KP-ABE Demonstration
    print("\n--- [3] Key-Policy ABE (KP-ABE) ---")
    mpk_kp, msk_kp = tool.kp_setup()
    key_policy = "FACILITY:LAB_A AND CLEARANCE:LEVEL_3"
    print(f"Secret Key Access Policy: {key_policy}")
    sk_kp = tool.kp_keygen(msk_kp, key_policy)

    # Encrypt with attributes
    ct_attrs = {"FACILITY:LAB_A", "CLEARANCE:LEVEL_3", "PROJECT:GENOME"}
    pkg_kp = tool.kp_encrypt_message(mpk_kp, ct_attrs, b"Genomic Research Sequence XYZ-99")
    dec_kp = tool.kp_decrypt_message(mpk_kp, pkg_kp, sk_kp)
    print(f"Decrypted KP-ABE payload: {dec_kp.decode()}")

    # 4. DFA KP-ABE Demonstration
    print("\n--- [4] DFA KP-ABE for Regular Languages ---")
    alphabet = set("ACGT")
    # DFA matching virus signature containing 'CGTA'
    pattern = "CGTA"
    dfa = DFA.from_pattern_substring(pattern, alphabet)
    mpk_dfa, msk_dfa = tool.dfa_setup(alphabet)
    sk_dfa = tool.dfa_keygen(msk_dfa, dfa)

    dna_stream = "AACGTAGGCT"
    print(f"DFA searching for signature: {pattern}")
    print(f"Testing DNA Stream: {dna_stream}")
    pkg_dfa = tool.dfa_encrypt_message(mpk_dfa, dna_stream, b"Threat Detected: Bio-Marker Alpha Identified")
    dec_dfa = tool.dfa_decrypt_message(mpk_dfa, pkg_dfa, sk_dfa)
    print(f"DFA Decrypted Alert: {dec_dfa.decode()}")

    print("\n" + "=" * 80)
    print("                  Demonstration Completed Successfully!")
    print("=" * 80)


def cmd_benchmark(args):
    print("=" * 80)
    print("       Running FABEO Cross-Paper Empirical Benchmarks (Section 7)")
    print("=" * 80)

    runner = BenchmarkRunner(curve_name="BLS12-381")
    attr_counts = [int(x) for x in args.attributes.split(",")]
    trials = args.trials

    print(f"Target Attributes: {attr_counts}")
    print(f"Number of Trials: {trials}")

    # CP-ABE Benchmark
    print("\nExecuting CP-ABE Benchmark (FABEO vs ABGW vs BSW)...")
    cp_metrics = runner.run_cp_benchmark(attribute_counts=attr_counts, trials=trials)
    BenchmarkPlotter.print_summary_table(cp_metrics)
    BenchmarkPlotter.print_speedup_analysis(cp_metrics)

    # KP-ABE Benchmark
    print("\nExecuting KP-ABE Benchmark (FABEO vs ABGW)...")
    kp_metrics = runner.run_kp_benchmark(attribute_counts=attr_counts, trials=trials)
    BenchmarkPlotter.print_summary_table(kp_metrics)

    # DFA Benchmark
    print("\nExecuting DFA KP-ABE Benchmark...")
    dfa_results = runner.run_dfa_benchmark(string_lengths=attr_counts, trials=trials)
    print("\n" + "-" * 85)
    print(f"{'Scheme':<15} | {'String Length':<15} | {'Enc Time(ms)':<15} | {'Dec Time(ms)':<15} | {'Pairings':<10}")
    print("-" * 85)
    for r in dfa_results:
        print(f"{r['scheme_name']:<15} | {r['string_length']:<15} | {r['enc_time_ms']:<15.2f} | {r['dec_time_ms']:<15.2f} | {r['pairings_dec']:<10}")
    print("-" * 85 + "\n")

    # Export results
    results_dir = os.path.join(SCRIPT_DIR, "results")
    BenchmarkExporter.export_to_json(cp_metrics + kp_metrics, os.path.join(results_dir, "benchmark_summary.json"))
    BenchmarkExporter.export_to_csv(cp_metrics + kp_metrics, os.path.join(results_dir, "benchmark_summary.csv"))
    print(f"Results exported to {results_dir}/benchmark_summary.csv and .json")


def cmd_test(args):
    print("=" * 80)
    print("               Running Complete FABEO Test Suite")
    print("=" * 80)

    import unittest
    tests_dir = os.path.join(SCRIPT_DIR, "tests")
    loader = unittest.TestLoader()
    suite = loader.discover(tests_dir, pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if not result.wasSuccessful():
        sys.exit(1)


def cmd_web(args):
    """Launch the Web Evaluation Dashboard Server."""
    from web_server import start_server
    start_server(port=args.port)


def main():
    parser = argparse.ArgumentParser(
        description="FABEO: Fast Attribute-Based Encryption with Optimal Security (CCS 2022)"
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Subcommand to execute")

    # demo
    p_demo = subparsers.add_parser("demo", help="Run end-to-end demonstration")
    p_demo.set_defaults(func=cmd_demo)

    # benchmark
    p_bench = subparsers.add_parser("benchmark", help="Run comparative benchmark suite")
    p_bench.add_argument("--attributes", default="10,20,50,100", help="Comma-separated attribute counts")
    p_bench.add_argument("--trials", type=int, default=3, help="Number of repetitions per test")
    p_bench.set_defaults(func=cmd_benchmark)

    # test
    p_test = subparsers.add_parser("test", help="Run unit test suite")
    p_test.set_defaults(func=cmd_test)

    # web
    p_web = subparsers.add_parser("web", help="Start web evaluation dashboard server")
    p_web.add_argument("--port", type=int, default=8080, help="Web server port (default: 8080)")
    p_web.set_defaults(func=cmd_web)

    args = parser.parse_args()
    if not args.subcommand:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
