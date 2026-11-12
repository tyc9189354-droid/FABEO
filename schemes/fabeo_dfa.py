#!/usr/bin/env python3
"""
================================================================================
FABEO: Fast Attribute-Based Encryption with Optimal Security
KP-ABE for Deterministic Finite Automata (DFA)
Reference: Figure 4 & Section 8.2
================================================================================
"""

from typing import Set, Dict, List, Tuple, Any, Optional
from ..core.pairing_group import PairingGroup, Zp, G1Element, G2Element, GTElement
from ..core.dfa import DFA
from .base_abe import BaseABE


class FabeoDFA(BaseABE):
    """
    FABEO KP-ABE Scheme for Regular Languages / Deterministic Finite Automata.
    Optimal, adaptive security in the GGM with randomness reuse.
    """

    def __init__(self, group: PairingGroup):
        super().__init__(group)

    def setup(self, alphabet: Set[str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Setup(1^lambda):
          alpha, w_start, w_end, z <-$ Z_p
          {w_sigma}_{sigma in Sigma} <-$ Z_p^|Sigma|
          mpk := (G, g1^w_start, g1^w_end, g1^z, {g1^w_sigma}, e(g1, g2)^alpha)
          msk := (alpha, w_start, w_end, z, {w_sigma})
        """
        alpha = self.group.random()
        w_start = self.group.random()
        w_end = self.group.random()
        z = self.group.random()

        w_sigma = {}
        g1_w_sigma = {}
        for sym in alphabet:
            w_s = self.group.random()
            w_sigma[sym] = w_s
            g1_w_sigma[sym] = self.group.g1 ** w_s

        g1_wstart = self.group.g1 ** w_start
        g1_wend = self.group.g1 ** w_end
        g1_z = self.group.g1 ** z
        eg1g2_alpha = self.group.pair(self.group.g1, self.group.g2) ** alpha

        mpk = {
            "type": "FABEO_DFA_MPK",
            "alphabet": list(alphabet),
            "g1_wstart": g1_wstart,
            "g1_wend": g1_wend,
            "g1_z": g1_z,
            "g1_w_sigma": g1_w_sigma,
            "eg1g2_alpha": eg1g2_alpha,
        }
        msk = {
            "type": "FABEO_DFA_MSK",
            "alpha": alpha,
            "w_start": w_start,
            "w_end": w_end,
            "z": z,
            "w_sigma": w_sigma,
        }
        return mpk, msk

    def keygen(self, msk: Dict[str, Any], dfa: DFA) -> Dict[str, Any]:
        """
        KeyGen(msk, (Q, Sigma, delta, F)):
          ru <-$ Z_p, du <-$ Z_p for all u in [Q]
          sk0 := g2^(d1 + w_start * r1)
          sk1,u := g2^ru for all u in [Q]
          sk2,u := g2^(-du + z * ru) for all u in [Q]
          sk3,u,sigma := g2^(dv + w_sigma * ru) for all u in [Q], sigma in Sigma, v = delta(u, sigma)
          sk4,u := g2^(alpha - du + w_end * ru) for all u in F
        """
        alpha = msk["alpha"]
        w_start = msk["w_start"]
        w_end = msk["w_end"]
        z = msk["z"]
        w_sigma = msk["w_sigma"]

        Q = dfa.num_states
        ru = {u: self.group.random() for u in range(1, Q + 1)}
        du = {u: self.group.random() for u in range(1, Q + 1)}

        # sk0 = g2^(d1 + w_start * r1)
        exp_sk0 = du[1] + (w_start * ru[1])
        sk0 = self.group.g2 ** exp_sk0

        # sk1,u = g2^ru
        sk1 = {u: self.group.g2 ** ru[u] for u in range(1, Q + 1)}

        # sk2,u = g2^(-du + z * ru)
        sk2 = {}
        for u in range(1, Q + 1):
            exp_sk2 = -du[u] + (z * ru[u])
            sk2[u] = self.group.g2 ** exp_sk2

        # sk3,u,sigma = g2^(dv + w_sigma * ru) where v = delta(u, sigma)
        sk3 = {}
        for (u, sym), v in dfa.transitions.items():
            exp_sk3 = du[v] + (w_sigma[sym] * ru[u])
            sk3[(u, sym)] = self.group.g2 ** exp_sk3

        # sk4,u = g2^(alpha - du + w_end * ru) for u in F
        sk4 = {}
        for u in dfa.accept_states:
            exp_sk4 = alpha - du[u] + (w_end * ru[u])
            sk4[u] = self.group.g2 ** exp_sk4

        return {
            "type": "FABEO_DFA_SK",
            "dfa": dfa,
            "sk0": sk0,
            "sk1": sk1,
            "sk2": sk2,
            "sk3": sk3,
            "sk4": sk4,
        }

    def encrypt(self, mpk: Dict[str, Any], x: List[str]) -> Tuple[Dict[str, Any], GTElement]:
        """
        Enc(mpk, x):
          Pick (sl, s0, s1, ..., sl-1) <-$ Z_p^(l+1) where l = |x|
          ct0 := g1^s0
          ct1 := g1^(s0 * w_start) = (g1_wstart)^s0
          ct2,i := g1^si for i in [l]
          ct3,i := g1^(s_{i-1} * z + si * w_{xi}) = (g1_z)^s_{i-1} * (g1_w_{xi})^si
          ct4 := g1^(sl * w_end) = (g1_wend)^sl
          d := e(g1, g2)^(alpha * sl)
        """
        l = len(x)
        if l == 0:
            raise ValueError("Input string x cannot be empty")

        # Randomness: sl, s0, s1, ..., sl-1
        s_l = self.group.random()
        s_arr = [self.group.random() for _ in range(l)]  # s[0] .. s[l-1]
        # s_arr[0] is s0, ..., s_arr[l-1] is s_{l-1}
        # In paper notation: s0 is s_arr[0], s_i is s_arr[i] for i < l, and s_l is s_l.
        # Let's align s_seq = [s0, s1, ..., s_{l-1}, s_l]
        s_seq = s_arr + [s_l]

        # ct0 = g1^s0
        ct0 = self.group.g1 ** s_seq[0]
        # ct1 = (g1_wstart)^s0
        ct1 = mpk["g1_wstart"] ** s_seq[0]

        # ct2,i = g1^si, ct3,i = g1^(s_{i-1}*z + s_i*w_{x_i}) for i in [1..l]
        ct2 = {}
        ct3 = {}
        for i in range(1, l + 1):
            sym = x[i - 1]
            s_i = s_seq[i]
            s_prev = s_seq[i - 1]

            ct2[i] = self.group.g1 ** s_i
            term_z = mpk["g1_z"] ** s_prev
            term_w = mpk["g1_w_sigma"][sym] ** s_i
            ct3[i] = term_z * term_w

        # ct4 = (g1_wend)^sl
        ct4 = mpk["g1_wend"] ** s_l

        # d = e(g1, g2)^(alpha * sl)
        d = mpk["eg1g2_alpha"] ** s_l

        ct = {
            "type": "FABEO_DFA_CT",
            "x": x,
            "ct0": ct0,
            "ct1": ct1,
            "ct2": ct2,
            "ct3": ct3,
            "ct4": ct4,
        }
        return ct, d

    def decrypt(self, mpk: Dict[str, Any], ct: Dict[str, Any], sk: Dict[str, Any]) -> GTElement:
        """
        Dec(mpk, x, (Q, Sigma, delta, F), ct, sk):
          Verify DFA accepts x. Get state sequence u1, ..., ul, fin.
          B := [ e(ct0, sk0) / e(ct1, sk1,1) ]
               * prod_{i=1}^l [ ( e(ct2_{i-1}, sk2_{ui}) * e(ct2_i, sk3_{ui, xi}) ) / e(ct3_i, sk1_{ui}) ]
          output B * [ e(ct2_l, sk4_fin) / e(ct4, sk1_fin) ]
        """
        dfa: DFA = sk["dfa"]
        x: List[str] = ct["x"]
        l = len(x)

        path_info = dfa.get_execution_path(x)
        if path_info is None:
            raise ValueError(f"DFA does not accept string: {''.join(x)}")

        states, fin = path_info
        # states has length l: u1, u2, ..., ul, where u1 = 1
        # u_{i+1} = delta(u_i, x_i) for i in [1..l-1], and fin = delta(u_l, x_l)

        # Part 1: e(ct0, sk0) / e(ct1, sk1,1)
        p1_num = self.group.pair(ct["ct0"], sk["sk0"])
        p1_den = self.group.pair(ct["ct1"], sk["sk1"][1])
        b_val = p1_num / p1_den

        # Part 2: Product over i in [1..l]
        # for i=1, ct2_prev is ct0
        for i in range(1, l + 1):
            sym = x[i - 1]
            u_i = states[i - 1]
            ct2_prev = ct["ct0"] if i == 1 else ct["ct2"][i - 1]
            ct2_curr = ct["ct2"][i]

            t_a = self.group.pair(ct2_prev, sk["sk2"][u_i])
            t_b = self.group.pair(ct2_curr, sk["sk3"][(u_i, sym)])
            t_c = self.group.pair(ct["ct3"][i], sk["sk1"][u_i])

            step_val = (t_a * t_b) / t_c
            b_val = b_val * step_val

        # Part 3: e(ct2_l, sk4_fin) / e(ct4, sk1_fin)
        p3_num = self.group.pair(ct["ct2"][l], sk["sk4"][fin])
        p3_den = self.group.pair(ct["ct4"], sk["sk1"][fin])
        p3_val = p3_num / p3_den

        d = b_val * p3_val
        return d
