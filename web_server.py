#!/usr/bin/env python3
"""
================================================================================
FABEO: Web Evaluation Server & API
Provides computational and storage cost evaluation endpoints and web dashboard.
================================================================================
"""

import os
import sys
import json
import time
import platform
import urllib.parse
from http.server import HTTPServer, SimpleHTTPRequestHandler
from typing import Dict, Any, List, Set, Optional

# Ensure parent directory is in sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

if "FABEO" not in sys.modules:
    import types
    pkg = types.ModuleType("FABEO")
    pkg.__path__ = [SCRIPT_DIR]
    pkg.__file__ = os.path.join(SCRIPT_DIR, "__init__.py")
    sys.modules["FABEO"] = pkg

from FABEO.core.pairing_group import PairingGroup
from FABEO.core.msp import MSP, PolicyParser
from FABEO.core.dfa import DFA
from FABEO.runner.benchmark_runner import BenchmarkRunner
from FABEO.core.metrics import SchemeMetrics
from FABEO.tool import FabeoTool


CURVE_SPECS = {
    "BLS12-381": {
        "security_bits": 128,
        "standard": "Zcash / Ethereum 2.0 / IETF BLS",
        "order_bits": 255,
        "compressed": {"g1": 48, "g2": 96, "gt": 288, "zp": 32},
        "uncompressed": {"g1": 96, "g2": 192, "gt": 576, "zp": 32},
    },
    "BN254": {
        "security_bits": 100,
        "standard": "Ethereum EVM / alt_bn128",
        "order_bits": 254,
        "compressed": {"g1": 32, "g2": 64, "gt": 192, "zp": 32},
        "uncompressed": {"g1": 64, "g2": 128, "gt": 384, "zp": 32},
    },
    "MNT224": {
        "security_bits": 96,
        "standard": "Paper Table 2 (Type-III MNT)",
        "order_bits": 224,
        "compressed": {"g1": 29, "g2": 171, "gt": 171, "zp": 28},
        "uncompressed": {"g1": 58, "g2": 342, "gt": 342, "zp": 28},
    },
}


def load_benchmark_summary() -> List[Dict[str, Any]]:
    json_path = os.path.join(SCRIPT_DIR, "results", "benchmark_summary.json")
    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error reading benchmark_summary.json: {e}")
    return []


def evaluate_custom_policy(policy_str: str, user_attributes: List[str], curve_name: str = "BLS12-381", compressed: bool = True) -> Dict[str, Any]:
    """
    Evaluates exact computational and storage metrics for a given policy and attribute set.
    """
    group = PairingGroup(curve_name=curve_name)
    curve_info = CURVE_SPECS.get(curve_name, CURVE_SPECS["BLS12-381"])
    sizes = curve_info["compressed"] if compressed else curve_info["uncompressed"]

    start_t = time.perf_counter_ns()
    try:
        msp = MSP.from_policy_string(group, policy_str)
    except Exception as e:
        return {"error": f"Policy syntax error: {str(e)}"}

    attr_set = {a.strip().upper() for a in user_attributes if a.strip()}
    sol = msp.solve_reconstruction_coefficients(attr_set)
    solve_ms = (time.perf_counter_ns() - start_t) / 1_000_000.0

    satisfied = sol is not None
    used_rows = list(sol.keys()) if satisfied else []
    I_len = len(used_rows)
    m = len(attr_set)
    n1 = msp.n1
    n2 = msp.n2
    tau = msp.tau

    def calc_bytes(g1_count: int, g2_count: int, gt_count: int, zp_count: int = 0) -> int:
        return (g1_count * sizes["g1"]) + (g2_count * sizes["g2"]) + (gt_count * sizes["gt"]) + (zp_count * sizes["zp"])

    # 1. FABEO CP-ABE
    # sk: (m + 1) G1 + 1 G2
    # ct: n1 G1 + (tau + 1) G2 + 1 GT
    # dec pairings: tau + 2 (constant 3 if tau=1)
    fabeo_sk_g1 = m + 1
    fabeo_sk_g2 = 1
    fabeo_ct_g1 = n1
    fabeo_ct_g2 = tau + 1
    fabeo_ct_gt = 1
    fabeo_pairings = tau + 2 if satisfied else 0

    # 2. ABGW CP-ABE
    # sk: 0 G1 + (m + 2) G2
    # ct: 3*n1 G1 + 0 G2 + 1 GT
    # dec pairings: |I| + 2
    abgw_sk_g1 = 0
    abgw_sk_g2 = m + 2
    abgw_ct_g1 = 3 * n1
    abgw_ct_g2 = 0
    abgw_ct_gt = 1
    abgw_pairings = I_len + 2 if satisfied else 0

    # 3. BSW CP-ABE
    # sk: (m + 1) G1 + m G2
    # ct: n1 G1 + (n1 + 1) G2 + 1 GT
    # dec pairings: 2*|I| + 1
    bsw_sk_g1 = m + 1
    bsw_sk_g2 = m
    bsw_ct_g1 = n1
    bsw_ct_g2 = n1 + 1
    bsw_ct_gt = 1
    bsw_pairings = 2 * I_len + 1 if satisfied else 0

    # 4. FAME CP-ABE
    # sk: (3m + 3) G1 + 3 G2
    # ct: 3*n1 G1 + 3 G2 + 1 GT
    # dec pairings: 6 (fixed)
    fame_sk_g1 = 3 * m + 3
    fame_sk_g2 = 3
    fame_ct_g1 = 3 * n1
    fame_ct_g2 = 3
    fame_ct_gt = 1
    fame_pairings = 6 if satisfied else 0

    schemes_eval = [
        {
            "name": "FABEO CP (CCS 2022)",
            "is_fabeo": True,
            "pairings": fabeo_pairings,
            "pairing_formula": f"tau + 2 = {tau} + 2 = {tau + 2}",
            "sk_g1": fabeo_sk_g1,
            "sk_g2": fabeo_sk_g2,
            "sk_bytes": calc_bytes(fabeo_sk_g1, fabeo_sk_g2, 0),
            "ct_g1": fabeo_ct_g1,
            "ct_g2": fabeo_ct_g2,
            "ct_gt": fabeo_ct_gt,
            "ct_bytes": calc_bytes(fabeo_ct_g1, fabeo_ct_g2, fabeo_ct_gt),
            "security": "Optimal O(t^2/p) GGM",
            "multi_use": f"Yes (tau={tau})",
        },
        {
            "name": "ABGW CP (CCS'17)",
            "is_fabeo": False,
            "pairings": abgw_pairings,
            "pairing_formula": f"|I| + 2 = {I_len} + 2 = {I_len + 2}",
            "sk_g1": abgw_sk_g1,
            "sk_g2": abgw_sk_g2,
            "sk_bytes": calc_bytes(abgw_sk_g1, abgw_sk_g2, 0),
            "ct_g1": abgw_ct_g1,
            "ct_g2": abgw_ct_g2,
            "ct_gt": abgw_ct_gt,
            "ct_bytes": calc_bytes(abgw_ct_g1, abgw_ct_g2, abgw_ct_gt),
            "security": "O(t^4/p)",
            "multi_use": "Yes",
        },
        {
            "name": "BSW CP (S&P'07)",
            "is_fabeo": False,
            "pairings": bsw_pairings,
            "pairing_formula": f"2|I| + 1 = 2({I_len}) + 1 = {2 * I_len + 1}",
            "sk_g1": bsw_sk_g1,
            "sk_g2": bsw_sk_g2,
            "sk_bytes": calc_bytes(bsw_sk_g1, bsw_sk_g2, 0),
            "ct_g1": bsw_ct_g1,
            "ct_g2": bsw_ct_g2,
            "ct_gt": bsw_ct_gt,
            "ct_bytes": calc_bytes(bsw_ct_g1, bsw_ct_g2, bsw_ct_gt),
            "security": "O(t^3/p) Generic",
            "multi_use": "Yes",
        },
        {
            "name": "FAME CP (CCS'17)",
            "is_fabeo": False,
            "pairings": fame_pairings,
            "pairing_formula": "6 (Constant)",
            "sk_g1": fame_sk_g1,
            "sk_g2": fame_sk_g2,
            "sk_bytes": calc_bytes(fame_sk_g1, fame_sk_g2, 0),
            "ct_g1": fame_ct_g1,
            "ct_g2": fame_ct_g2,
            "ct_gt": fame_ct_gt,
            "ct_bytes": calc_bytes(fame_ct_g1, fame_ct_g2, fame_ct_gt),
            "security": "O(t^4/p) Standard",
            "multi_use": "No (tau=1 only)",
        },
    ]

    return {
        "success": True,
        "policy": policy_str,
        "user_attributes": list(attr_set),
        "satisfied": satisfied,
        "solve_ms": round(solve_ms, 3),
        "msp": {
            "matrix_rows": n1,
            "matrix_cols": n2,
            "tau": tau,
            "pi": msp.pi,
            "used_rows": used_rows,
            "satisfying_subset_size": I_len,
        },
        "curve": {
            "name": curve_name,
            "compressed": compressed,
            "specs": curve_info,
        },
        "comparison": schemes_eval,
    }


class FabeoEvaluationHandler(SimpleHTTPRequestHandler):
    """Custom HTTP handler serving the web evaluation dashboard and REST API."""

    def __init__(self, *args, **kwargs):
        # Serve static files from web directory
        web_dir = os.path.join(SCRIPT_DIR, "web")
        super().__init__(*args, directory=web_dir, **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/benchmark-data":
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            data = load_benchmark_summary()
            runner = BenchmarkRunner()
            dfa_data = runner.run_dfa_benchmark([10, 20, 50, 100], trials=1)

            resp = {
                "benchmarks": data,
                "dfa_benchmarks": dfa_data,
                "curves": CURVE_SPECS,
                "system": {
                    "platform": platform.platform(),
                    "processor": platform.processor(),
                    "python": platform.python_version(),
                },
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        elif path == "/api/system-info":
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            info = {
                "platform": platform.platform(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "python_version": platform.python_version(),
                "curves": list(CURVE_SPECS.keys()),
            }
            self.wfile.write(json.dumps(info).encode("utf-8"))
            return

        super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)

        try:
            req_json = json.loads(post_data.decode("utf-8")) if post_data else {}
        except Exception:
            req_json = {}

        if path == "/api/evaluate-policy":
            policy_str = req_json.get("policy", "(ATTR_1 AND ATTR_2) OR ATTR_3")
            user_attrs = req_json.get("attributes", ["ATTR_1", "ATTR_2"])
            curve_name = req_json.get("curve", "BLS12-381")
            compressed = req_json.get("compressed", True)

            eval_res = evaluate_custom_policy(policy_str, user_attrs, curve_name, compressed)

            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(eval_res).encode("utf-8"))
            return

        elif path == "/api/run-benchmark":
            attribute_counts = req_json.get("attributes", [10, 20, 50])
            trials = req_json.get("trials", 1)
            curve_name = req_json.get("curve", "BLS12-381")

            # Execute real benchmark
            runner = BenchmarkRunner(curve_name=curve_name)
            cp_results = runner.run_cp_benchmark(attribute_counts=attribute_counts, trials=trials)
            kp_results = runner.run_kp_benchmark(attribute_counts=attribute_counts, trials=trials)
            dfa_results = runner.run_dfa_benchmark([10, 20, 50, 100], trials=trials)

            results_dicts = [m.to_dict() for m in cp_results + kp_results]

            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({
                "success": True, 
                "results": results_dicts,
                "dfa_results": dfa_results
            }).encode("utf-8"))
            return

        elif path == "/api/crypto-demo":
            scheme = req_json.get("scheme", "FABEO_CP")
            policy_str = req_json.get("policy", "(MEDICINE:DOCTOR AND DEPT:CARDIOLOGY) OR ROLE:DIRECTOR")
            user_attrs = req_json.get("attributes", ["MEDICINE:DOCTOR", "DEPT:CARDIOLOGY"])
            message_text = req_json.get("message", "機密基因定序與病歷機密資訊 (Confidential Genomic Profile #7829)")
            curve_name = req_json.get("curve", "BLS12-381")

            try:
                tool = FabeoTool(curve_name=curve_name)
                msg_bytes = message_text.encode("utf-8")

                if scheme == "FABEO_KP":
                    t0 = time.perf_counter_ns()
                    mpk, msk = tool.kp_setup()
                    t_setup = (time.perf_counter_ns() - t0) / 1_000_000.0

                    t0 = time.perf_counter_ns()
                    sk = tool.kp_keygen(msk, policy_str)
                    t_keygen = (time.perf_counter_ns() - t0) / 1_000_000.0

                    t0 = time.perf_counter_ns()
                    pkg = tool.kp_encrypt_message(mpk, set(user_attrs), msg_bytes)
                    t_enc = (time.perf_counter_ns() - t0) / 1_000_000.0

                    t0 = time.perf_counter_ns()
                    try:
                        dec = tool.kp_decrypt_message(mpk, pkg, sk)
                        t_dec = (time.perf_counter_ns() - t0) / 1_000_000.0
                        satisfied = True
                        dec_text = dec.decode("utf-8", errors="replace")
                    except Exception:
                        t_dec = (time.perf_counter_ns() - t0) / 1_000_000.0
                        satisfied = False
                        dec_text = None

                    pairings = len(user_attrs) + 1

                elif scheme == "FABEO_DFA":
                    word = req_json.get("word", "CGTA")
                    t0 = time.perf_counter_ns()
                    alphabet = set(word) | {"A", "C", "G", "T", "0", "1"}
                    mpk, msk = tool.dfa_setup(alphabet)
                    t_setup = (time.perf_counter_ns() - t0) / 1_000_000.0

                    dfa = DFA.from_exact_word(word, alphabet)

                    t0 = time.perf_counter_ns()
                    sk = tool.dfa_keygen(msk, dfa)
                    t_keygen = (time.perf_counter_ns() - t0) / 1_000_000.0

                    t0 = time.perf_counter_ns()
                    pkg = tool.dfa_encrypt_message(mpk, word, msg_bytes)
                    t_enc = (time.perf_counter_ns() - t0) / 1_000_000.0

                    t0 = time.perf_counter_ns()
                    try:
                        dec = tool.dfa_decrypt_message(mpk, pkg, sk)
                        t_dec = (time.perf_counter_ns() - t0) / 1_000_000.0
                        satisfied = True
                        dec_text = dec.decode("utf-8", errors="replace")
                    except Exception:
                        t_dec = (time.perf_counter_ns() - t0) / 1_000_000.0
                        satisfied = False
                        dec_text = None

                    pairings = len(word) + 2

                else:  # Default FABEO_CP
                    t0 = time.perf_counter_ns()
                    mpk, msk = tool.cp_setup()
                    t_setup = (time.perf_counter_ns() - t0) / 1_000_000.0

                    t0 = time.perf_counter_ns()
                    sk = tool.cp_keygen(msk, set(user_attrs))
                    t_keygen = (time.perf_counter_ns() - t0) / 1_000_000.0

                    t0 = time.perf_counter_ns()
                    pkg = tool.cp_encrypt_message(mpk, policy_str, msg_bytes)
                    t_enc = (time.perf_counter_ns() - t0) / 1_000_000.0

                    t0 = time.perf_counter_ns()
                    try:
                        dec = tool.cp_decrypt_message(mpk, pkg, sk)
                        t_dec = (time.perf_counter_ns() - t0) / 1_000_000.0
                        satisfied = True
                        dec_text = dec.decode("utf-8", errors="replace")
                    except Exception:
                        t_dec = (time.perf_counter_ns() - t0) / 1_000_000.0
                        satisfied = False
                        dec_text = None

                    pairings = 3  # Constant!

                resp = {
                    "success": True,
                    "scheme": scheme,
                    "curve": curve_name,
                    "satisfied": satisfied,
                    "original_message": message_text,
                    "decrypted_message": dec_text,
                    "timings": {
                        "setup_ms": round(t_setup, 3),
                        "keygen_ms": round(t_keygen, 3),
                        "encrypt_ms": round(t_enc, 3),
                        "decrypt_ms": round(t_dec, 3),
                        "total_ms": round(t_setup + t_keygen + t_enc + t_dec, 3),
                    },
                    "pairings": pairings,
                    "status_message": "✓ 驗證成功：明文完整還原，存取策略符合！" if satisfied else "✗ 驗證失敗：解密者屬性未滿足存取策略矩陣 (Access Denied)"
                }
            except Exception as ex:
                resp = {"success": False, "error": str(ex)}

            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


def start_server(port: int = 8080):
    server_address = ("", port)
    httpd = HTTPServer(server_address, FabeoEvaluationHandler)
    print("=" * 75)
    print(f"🚀 FABEO Performance & Storage Cost Evaluator Web Server Running")
    print(f"👉 Local Access URL: http://localhost:{port}")
    print("=" * 75)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping web server...")
        httpd.server_close()


if __name__ == "__main__":
    port = 8080
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])
    start_server(port)
