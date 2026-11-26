#!/usr/bin/env python3
"""
================================================================================
Baseline: FAME KP-ABE Scheme (Agrawal & Chase, ACM CCS 2017)
Official Paper Reference Implementation (AC17 KP-ABE, k=2)
================================================================================
"""

from typing import Set, Dict, List, Tuple, Any, Optional
from ..core.pairing_group import PairingGroup, Zp, G1Element, G2Element, GTElement
from ..core.msp import MSP
from .base_abe import BaseABE


class FameKP(BaseABE):
    """
    AC17 / FAME KP-ABE Scheme for Monotone Span Programs under the k-linear (DLIN, k=2) assumption.
    Decryption requires constant 2*(k+1) = 6 pairings.
    """

    def __init__(self, group: PairingGroup, assump_size: int = 2):
        super().__init__(group)
        self.assump_size = assump_size

    def setup(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        k = self.assump_size
        A = [self.group.random() for _ in range(k)]
        B = [self.group.random() for _ in range(k)]
        k_vec = [self.group.random() for _ in range(k + 1)]

        g = self.group.g1
        h = self.group.g2
        e_gh = self.group.pair(g, h)

        h_A = [h ** A[i] for i in range(k)] + [h]
        g_k = [g ** k_vec[i] for i in range(k + 1)]
        e_gh_kA = [e_gh ** (k_vec[i] * A[i] + k_vec[k]) for i in range(k)]

        mpk = {
            "type": "FAME_KP_MPK",
            "assump_size": k,
            "h_A": h_A,
            "e_gh_kA": e_gh_kA,
        }
        msk = {
            "type": "FAME_KP_MSK",
            "assump_size": k,
            "g": g,
            "h": h,
            "g_k": g_k,
            "A": A,
            "B": B,
        }
        return mpk, msk

    def encrypt(self, mpk: Dict[str, Any], attributes: Set[str]) -> Tuple[Dict[str, Any], GTElement]:
        k = self.assump_size
        p = self.group.order
        s = [self.group.random() for _ in range(k)]
        s_sum = sum(int(x) for x in s) % p

        C_0 = [mpk["h_A"][i] ** s[i] for i in range(k)] + [mpk["h_A"][k] ** s_sum]

        C = {}
        for attr in attributes:
            u_clean = attr.strip().upper()
            ct = []
            for l in range(k + 1):
                prod = self.group.g1 ** 0
                for t in range(k):
                    h_val = self.group.hash_to_g1(f"{u_clean}{l}{t}")
                    prod = prod * (h_val ** s[t])
                ct.append(prod)
            C[u_clean] = ct

        d = self.group.gt ** 0
        for i in range(k):
            d = d * (mpk["e_gh_kA"][i] ** s[i])

        ct = {
            "type": "FAME_KP_CT",
            "attributes": list(C.keys()),
            "C_0": C_0,
            "C": C,
        }
        return ct, d

    def keygen(self, msk: Dict[str, Any], policy_or_msp: Any) -> Dict[str, Any]:
        if isinstance(policy_or_msp, str):
            msp = MSP.from_policy_string(self.group, policy_or_msp)
        elif isinstance(policy_or_msp, MSP):
            msp = policy_or_msp
        else:
            raise TypeError("Expected policy string or MSP object")

        k = self.assump_size
        p = self.group.order
        r = [self.group.random() for _ in range(k)]
        r_sum = sum(int(x) for x in r) % p

        Br = [(int(msk["B"][i]) * int(r[i])) % p for i in range(k)] + [r_sum]
        K_0 = [msk["h"] ** br for br in Br]

        # precompute hash table
        hash_table = []
        for j in range(msp.n2):
            x_l = []
            for l in range(k + 1):
                y_t = []
                for t in range(k):
                    y_t.append(self.group.hash_to_g1(f"0{j+1}{l}{t}"))
                x_l.append(y_t)
            hash_table.append(x_l)

        # pick sigmaCol
        sigma_col = [0] + [self.group.random() for _ in range(msp.n2 - 1)]

        K = {}
        for row_idx in range(msp.n1):
            attr = msp.pi[row_idx]
            row = msp.matrix[row_idx]
            cols = len(row)
            sigma_attr = self.group.random()
            sk_row = []

            for t in range(k):
                inv_at = pow(int(msk["A"][t]), -1, p)
                prod = msk["g"] ** ((int(sigma_attr) * inv_at) % p)
                prod = prod * (msk["g_k"][t] ** row[0])

                for l in range(k + 1):
                    prod1 = self.group.hash_to_g1(f"{attr}{l}{t}")
                    for j in range(1, cols):
                        if row[j] != 0:
                            prod1 = prod1 * (hash_table[j][l][t] ** row[j])
                    exp_br = (Br[l] * inv_at) % p
                    prod = prod * (prod1 ** exp_br)

                exp_sigma = sum((int(sigma_col[j]) * inv_at * row[j]) for j in range(1, cols)) % p
                prod = prod * (msk["g"] ** exp_sigma)
                sk_row.append(prod)

            sk_last = (msk["g"] ** (-int(sigma_attr))) * (msk["g_k"][k] ** row[0])
            for j in range(1, cols):
                if row[j] != 0:
                    sk_last = sk_last * (msk["g"] ** ((int(sigma_col[j]) * row[j]) % p))
            sk_row.append(sk_last)

            K[row_idx] = sk_row

        return {
            "type": "FAME_KP_SK",
            "msp": msp,
            "K_0": K_0,
            "K": K,
        }

    def decrypt(self, mpk: Dict[str, Any], ct: Dict[str, Any], sk: Dict[str, Any]) -> GTElement:
        msp: MSP = sk["msp"]
        ct_attrs = set(ct["attributes"])
        coeff_map = msp.solve_reconstruction_coefficients(ct_attrs)
        if coeff_map is None:
            raise ValueError("Ciphertext attributes do not satisfy key access policy!")

        k = self.assump_size
        prod1_GT = self.group.gt ** 0
        prod2_GT = self.group.gt ** 0

        for l in range(k + 1):
            prod_H = self.group.g1 ** 0
            prod_G = self.group.g1 ** 0
            for row_idx, gamma in coeff_map.items():
                attr = msp.pi[row_idx]
                prod_H = prod_H * (sk["K"][row_idx][l] ** gamma)
                prod_G = prod_G * (ct["C"][attr][l] ** gamma)
            prod1_GT = prod1_GT * self.group.pair(prod_H, ct["C_0"][l])
            prod2_GT = prod2_GT * self.group.pair(prod_G, sk["K_0"][l])

        d = prod1_GT / prod2_GT
        return d
