#!/usr/bin/env python3
"""
================================================================================
Baseline: Waters 2012 DFA-based Functional Encryption (Waters, PKC 2012)
Transferred to asymmetric Type-III bilinear group setting
Official Reference: Doreen Riepel / FABEO / waters12dfa
================================================================================
"""

from typing import List, Dict, Set, Tuple, Any, Optional
from ..core.pairing_group import PairingGroup, Zp, G1Element, G2Element, GTElement
from ..core.dfa import DFA
from .base_abe import BaseABE


class WatersDFA(BaseABE):
    """
    Waters 2012 DFA-based Functional Encryption (Asymmetric Type-III).
    Decryption requires 2*|x| + 3 pairings.
    """

    def __init__(self, group: PairingGroup):
        super().__init__(group)

    def setup(self, alphabet: Set[str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        g = self.group.g1
        h = self.group.g2
        e_gh = self.group.pair(g, h)

        w_start = self.group.random()
        w_end = self.group.random()
        z = self.group.random()

        w = {"start": w_start, "end": w_end}
        for sigma in alphabet:
            w[str(sigma)] = self.group.random()

        g_w = {label: g ** w_i for label, w_i in w.items()}
        g_z = g ** z

        alpha = self.group.random()
        e_gh_alpha = e_gh ** alpha

        mpk = {
            "type": "WATERS_DFA_MPK",
            "g": g,
            "g_z": g_z,
            "g_w": g_w,
            "e_gh_alpha": e_gh_alpha,
            "alphabet": set(alphabet),
        }
        msk = {
            "type": "WATERS_DFA_MSK",
            "h": h,
            "z": z,
            "w": w,
            "alpha": alpha,
        }
        return mpk, msk

    def keygen(self, msk: Dict[str, Any], dfa: DFA) -> Dict[str, Any]:
        h = msk["h"]
        w = msk["w"]
        z = msk["z"]
        alpha = msk["alpha"]

        # Associate d_u with each state u in 1..num_states
        d = {u: self.group.random() for u in range(1, dfa.num_states + 1)}
        r_start = self.group.random()

        K = {}
        K["start1"] = h ** (d[1] + w["start"] * r_start)
        K["start2"] = h ** r_start

        # For each transition t = (u, sigma) -> v
        for (u, sigma), v in dfa.transitions.items():
            rx = self.group.random()
            key_t = (u, str(sigma))
            K[key_t] = {
                1: h ** (-d[u] + z * rx),
                2: h ** rx,
                3: h ** (d[v] + w[str(sigma)] * rx),
            }

        # For each accept state
        K_end = {}
        for x in dfa.accept_states:
            rx = self.group.random()
            K_end[x] = {
                1: h ** (alpha - d[x] + w["end"] * rx),
                2: h ** rx,
            }

        return {
            "type": "WATERS_DFA_SK",
            "dfa": dfa,
            "K": K,
            "K_end": K_end,
        }

    def encrypt(self, mpk: Dict[str, Any], x: List[str]) -> Tuple[Dict[str, Any], GTElement]:
        l = len(x)
        if l == 0:
            raise ValueError("Input string x cannot be empty")

        s = [self.group.random() for _ in range(l + 1)]  # s[0] .. s[l]
        d = mpk["e_gh_alpha"] ** s[l]

        C = {}
        C[0] = {
            1: mpk["g"] ** s[0],
            2: mpk["g_w"]["start"] ** s[0],
        }

        for i in range(1, l + 1):
            sym = str(x[i - 1])
            C[i] = {
                1: mpk["g"] ** s[i],
                2: (mpk["g_z"] ** s[i - 1]) * (mpk["g_w"][sym] ** s[i]),
            }

        C["end"] = mpk["g_w"]["end"] ** s[l]

        ct = {
            "type": "WATERS_DFA_CT",
            "C": C,
            "x": x,
        }
        return ct, d

    def decrypt(self, mpk: Dict[str, Any], ct: Dict[str, Any], sk: Dict[str, Any]) -> GTElement:
        dfa: DFA = sk["dfa"]
        x: List[str] = ct["x"]
        l = len(x)

        path_info = dfa.get_execution_path(x)
        if path_info is None:
            raise ValueError(f"DFA does not accept string: {''.join(x)}")

        states, fin = path_info
        C = ct["C"]
        K = sk["K"]

        # B[0] = e(C[0][1], K['start1']) / e(C[0][2], K['start2'])
        B = self.group.pair(C[0][1], K["start1"]) / self.group.pair(C[0][2], K["start2"])

        for i in range(1, l + 1):
            sym = str(x[i - 1])
            u_i = states[i - 1]
            key_t = (u_i, sym)
            k_t = K[key_t]

            t1 = self.group.pair(C[i - 1][1], k_t[1])
            t2 = self.group.pair(C[i][2], k_t[2])
            t3 = self.group.pair(C[i][1], k_t[3])

            B = B * (t1 / t2) * t3

        end_k = sk["K_end"][fin]
        b_end = B * self.group.pair(C[l][1], end_k[1]) / self.group.pair(C["end"], end_k[2])
        return b_end
