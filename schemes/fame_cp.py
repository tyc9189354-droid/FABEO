#!/usr/bin/env python3
"""
================================================================================
Baseline: FAME CP-ABE Scheme (Agrawal & Chase, ACM CCS 2017)
================================================================================
"""

from typing import Set, Dict, List, Tuple, Any
from ..core.pairing_group import PairingGroup, Zp, G1Element, G2Element, GTElement
from ..core.msp import MSP
from .base_abe import BaseABE


class FameCP(BaseABE):
    """
    FAME CP-ABE Scheme.
    Uses DLIN tuples in G^3. Decryption uses 6 pairings (constant for tau=1).
    """

    def __init__(self, group: PairingGroup):
        super().__init__(group)

    def setup(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        # FAME master key has d1, d2, d3 and bases
        d1 = self.group.random()
        d2 = self.group.random()
        d3 = self.group.random()

        # Matrices / basis elements
        a1 = self.group.random()
        a2 = self.group.random()

        # e(g1, g2)^d3 is blinder
        eg1g2_d3 = self.group.pair(self.group.g1, self.group.g2) ** d3

        mpk = {
            "type": "FAME_CP_MPK",
            "a1": a1,
            "a2": a2,
            "eg1g2_d3": eg1g2_d3,
            "g2_a1": self.group.g2 ** a1,
            "g2_a2": self.group.g2 ** a2,
        }
        msk = {
            "type": "FAME_CP_MSK",
            "d1": d1,
            "d2": d2,
            "d3": d3,
            "a1": a1,
            "a2": a2,
        }
        return mpk, msk

    def keygen(self, msk: Dict[str, Any], attributes: Set[str]) -> Dict[str, Any]:
        d1, d2, d3 = msk["d1"], msk["d2"], msk["d3"]
        a1, a2 = msk["a1"], msk["a2"]
        r1 = self.group.random()
        r2 = self.group.random()

        # sk0 has 3 G1 elements
        sk0 = [
            (self.group.g1 ** d1) * (self.group.g1 ** (r1 * a1)),
            (self.group.g1 ** d2) * (self.group.g1 ** (r2 * a2)),
            (self.group.g1 ** d3) * (self.group.g1 ** (r1 + r2)),
        ]

        # For each attribute: 3 G1 elements
        sk_u = {}
        for attr in attributes:
            u_clean = attr.strip().upper()
            sigma_u = self.group.random()
            h_u = self.group.hash_to_g1(u_clean)
            sk_u[u_clean] = [
                h_u ** (r1 / a1),
                h_u ** (r2 / a2),
                h_u ** (r1 + r2),
            ]

        # 3 G2 elements
        sk_g2 = [
            self.group.g2 ** (r1 / a1),
            self.group.g2 ** (r2 / a2),
            self.group.g2 ** (r1 + r2),
        ]

        return {
            "type": "FAME_CP_SK",
            "attributes": list(sk_u.keys()),
            "sk0": sk0,
            "sk_u": sk_u,
            "sk_g2": sk_g2,
        }

    def encrypt(self, mpk: Dict[str, Any], policy_or_msp: Any) -> Tuple[Dict[str, Any], GTElement]:
        if isinstance(policy_or_msp, str):
            msp = MSP.from_policy_string(self.group, policy_or_msp)
        else:
            msp = policy_or_msp

        n1, n2 = msp.n1, msp.n2
        s1 = self.group.random()
        s2 = self.group.random()

        # ct0 has 3 G2 elements
        ct0 = [
            mpk["g2_a1"] ** s1,
            mpk["g2_a2"] ** s2,
            self.group.g2 ** (s1 + s2),
        ]

        # ct_rows: 3 G1 elements per row
        ct_rows = []
        p = self.group.order
        for i in range(n1):
            h_pi = self.group.hash_to_g1(msp.pi[i])
            r_row = self.group.random()
            ct_rows.append([
                h_pi ** s1,
                h_pi ** s2,
                h_pi ** (s1 + s2),
            ])

        d = mpk["eg1g2_d3"] ** (s1 + s2)
        ct = {
            "type": "FAME_CP_CT",
            "msp": msp,
            "ct0": ct0,
            "ct_rows": ct_rows,
        }
        return ct, d

    def decrypt(self, mpk: Dict[str, Any], ct: Dict[str, Any], sk: Dict[str, Any]) -> GTElement:
        msp: MSP = ct["msp"]
        sk_attrs = set(sk["attributes"])
        coeff_map = msp.solve_reconstruction_coefficients(sk_attrs)
        if coeff_map is None:
            raise ValueError("Attributes do not satisfy access policy!")

        # 6 pairing operations in FAME:
        # 3 pairings for sk0 with ct0
        p1 = self.group.pair(sk["sk0"][0], ct["ct0"][0])
        p2 = self.group.pair(sk["sk0"][1], ct["ct0"][1])
        p3 = self.group.pair(sk["sk0"][2], ct["ct0"][2])

        # 3 pairings for aggregated ct_rows with sk_g2
        agg_ct = [self.group.g1 ** 0, self.group.g1 ** 0, self.group.g1 ** 0]
        for i, gamma_i in coeff_map.items():
            for k in range(3):
                agg_ct[k] = agg_ct[k] * (ct["ct_rows"][i][k] ** gamma_i)

        q1 = self.group.pair(agg_ct[0], sk["sk_g2"][0])
        q2 = self.group.pair(agg_ct[1], sk["sk_g2"][1])
        q3 = self.group.pair(agg_ct[2], sk["sk_g2"][2])

        # Reconstructed key
        d = (p3 * q3) / (p1 * p2 * q1 * q2)
        return d
