#!/usr/bin/env python3
"""
================================================================================
Baseline: BSW CP-ABE Scheme (Bethencourt, Sahai, Waters S&P 2007)
Asymmetric Type-III Bilinear Group Variant (Agrawal & Chase, CCS 2017 App D)
================================================================================
"""

from typing import Set, Dict, List, Tuple, Any
from ..core.pairing_group import PairingGroup, Zp, G1Element, G2Element, GTElement
from ..core.msp import MSP
from .base_abe import BaseABE


class BswCP(BaseABE):
    """
    BSW CP-ABE scheme (asymmetric Type-III).
    Decryption requires 2 * |I| + 1 pairings.
    """

    def __init__(self, group: PairingGroup):
        super().__init__(group)

    def setup(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        alpha = self.group.random()
        beta = self.group.random()
        g2_beta = self.group.g2 ** beta
        eg1g2_alpha = self.group.pair(self.group.g1, self.group.g2) ** alpha

        mpk = {
            "type": "BSW_CP_MPK",
            "g2_beta": g2_beta,
            "eg1g2_alpha": eg1g2_alpha,
        }
        msk = {
            "type": "BSW_CP_MSK",
            "alpha": alpha,
            "beta": beta,
        }
        return mpk, msk

    def keygen(self, msk: Dict[str, Any], attributes: Set[str]) -> Dict[str, Any]:
        alpha = msk["alpha"]
        beta = msk["beta"]
        p = self.group.order
        r = self.group.random()

        inv_beta = beta.inverse()
        exp_sk0 = (alpha + r) * inv_beta
        sk0 = self.group.g1 ** exp_sk0

        sk1 = {}
        sk2 = {}
        for attr in attributes:
            u_clean = attr.strip().upper()
            r_u = self.group.random()
            h_u = self.group.hash_to_g1(u_clean)
            sk1[u_clean] = (self.group.g1 ** r) * (h_u ** r_u)
            sk2[u_clean] = self.group.g2 ** r_u

        return {
            "type": "BSW_CP_SK",
            "attributes": list(sk1.keys()),
            "sk0": sk0,
            "sk1": sk1,
            "sk2": sk2,
        }

    def encrypt(self, mpk: Dict[str, Any], policy_or_msp: Any) -> Tuple[Dict[str, Any], GTElement]:
        if isinstance(policy_or_msp, str):
            msp = MSP.from_policy_string(self.group, policy_or_msp)
        else:
            msp = policy_or_msp

        n1, n2 = msp.n1, msp.n2
        s1 = self.group.random()
        v = [self.group.random() for _ in range(n2 - 1)]
        s_vec = [s1] + v
        p = self.group.order

        ct0 = mpk["g2_beta"] ** s1
        ct1 = []
        ct2 = []

        for i in range(n1):
            mu_i = 0
            for k in range(n2):
                if msp.matrix[i][k] != 0:
                    mu_i = (mu_i + msp.matrix[i][k] * int(s_vec[k])) % p

            ct1.append(self.group.g2 ** mu_i)
            h_pi = self.group.hash_to_g1(msp.pi[i])
            ct2.append(h_pi ** mu_i)

        d = mpk["eg1g2_alpha"] ** s1
        ct = {
            "type": "BSW_CP_CT",
            "msp": msp,
            "ct0": ct0,
            "ct1": ct1,
            "ct2": ct2,
        }
        return ct, d

    def decrypt(self, mpk: Dict[str, Any], ct: Dict[str, Any], sk: Dict[str, Any]) -> GTElement:
        msp: MSP = ct["msp"]
        sk_attrs = set(sk["attributes"])
        coeff_map = msp.solve_reconstruction_coefficients(sk_attrs)
        if coeff_map is None:
            raise ValueError("Attributes do not satisfy access policy!")

        # Term 0: e(sk0, ct0) = e(g1, g2)^(alpha * s1 + r * s1)
        term0 = self.group.pair(sk["sk0"], ct["ct0"])

        # Reconstruct e(g1, g2)^(r * s1) using 2*|I| pairings
        r_s1_gt = self.group.gt ** 0
        for i, gamma_i in coeff_map.items():
            attr = msp.pi[i]
            p1 = self.group.pair(sk["sk1"][attr], ct["ct1"][i])
            p2 = self.group.pair(ct["ct2"][i], sk["sk2"][attr])
            ratio = (p1 / p2) ** gamma_i
            r_s1_gt = r_s1_gt * ratio

        return term0 / r_s1_gt
