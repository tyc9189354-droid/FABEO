#!/usr/bin/env python3
"""
================================================================================
Baseline: ABGW KP-ABE Scheme (Ambrona et al., ACM CCS 2017)
Specified in Appendix C of the FABEO paper
================================================================================
"""

from typing import Set, Dict, List, Tuple, Any
from ..core.pairing_group import PairingGroup, Zp, G1Element, G2Element, GTElement
from ..core.msp import MSP
from .base_abe import BaseABE


class AbgwKP(BaseABE):
    """
    ABGW KP-ABE Scheme.
    Requires 2 * |I| pairings for decryption.
    """

    def __init__(self, group: PairingGroup):
        super().__init__(group)

    def setup(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Setup(1^lambda):
          alpha <-$ Z_p, b <-$ Z_p^2
          mpk := (G, g1^b[1], g1^b[2], e(g1, g2)^alpha)
          msk := (alpha, b)
        """
        alpha = self.group.random()
        b = [self.group.random(), self.group.random()]

        g1_b = [self.group.g1 ** b[0], self.group.g1 ** b[1]]
        eg1g2_alpha = self.group.pair(self.group.g1, self.group.g2) ** alpha

        mpk = {
            "type": "ABGW_KP_MPK",
            "g1_b": g1_b,
            "eg1g2_alpha": eg1g2_alpha,
        }
        msk = {
            "type": "ABGW_KP_MSK",
            "alpha": alpha,
            "b": b,
        }
        return mpk, msk

    def keygen(self, msk: Dict[str, Any], policy_or_msp: Any) -> Dict[str, Any]:
        """
        KeyGen(msk, (M, pi)):
          r <-$ Z_p^(n2-1). mu_i := M_i (alpha || r)^T
          sk1,i := g2^mu_i
          sk2,i := g2^( mu_i / (b[1] + pi(i)*b[2]) )
        """
        if isinstance(policy_or_msp, str):
            msp = MSP.from_policy_string(self.group, policy_or_msp)
        else:
            msp = policy_or_msp

        alpha = msk["alpha"]
        b = msk["b"]
        n1, n2 = msp.n1, msp.n2
        p = self.group.order

        r = [self.group.random() for _ in range(n2 - 1)]
        v_full = [alpha] + r

        sk1 = []
        sk2 = []
        for i in range(n1):
            mu_i = 0
            for k in range(n2):
                if msp.matrix[i][k] != 0:
                    mu_i = (mu_i + msp.matrix[i][k] * int(v_full[k])) % p

            sk1.append(self.group.g2 ** mu_i)

            u_clean = msp.pi[i]
            u_val = int.from_bytes(self.group.hash_to_g1(u_clean).to_bytes(32), "big") % p
            denom = (int(b[0]) + u_val * int(b[1])) % p
            if denom == 0:
                denom = 1
            inv_denom = pow(denom, -1, p)
            exp_val = (mu_i * inv_denom) % p
            sk2.append(self.group.g2 ** exp_val)

        return {
            "type": "ABGW_KP_SK",
            "msp": msp,
            "sk1": sk1,
            "sk2": sk2,
        }

    def encrypt(self, mpk: Dict[str, Any], attributes: Set[str]) -> Tuple[Dict[str, Any], GTElement]:
        """
        Enc(mpk, S):
          (s1 || s') <-$ Z_p x Z_p^|S|
          ct1,u := g1^(s1 - s'[u])
          ct2,u := (g1^b[1] * (g1^b[2])^u)^s'[u]
          d := e(g1, g2)^(alpha * s1)
        """
        s1 = self.group.random()
        g1_b = mpk["g1_b"]
        p = self.group.order

        ct1 = {}
        ct2 = {}
        for attr in attributes:
            u_clean = attr.strip().upper()
            s_prime_u = self.group.random()

            ct1[u_clean] = self.group.g1 ** (s1 - s_prime_u)

            u_val = int.from_bytes(self.group.hash_to_g1(u_clean).to_bytes(32), "big") % p
            base2 = g1_b[0] * (g1_b[1] ** u_val)
            ct2[u_clean] = base2 ** s_prime_u

        d = mpk["eg1g2_alpha"] ** s1
        ct = {
            "type": "ABGW_KP_CT",
            "attributes": list(ct1.keys()),
            "ct1": ct1,
            "ct2": ct2,
        }
        return ct, d

    def decrypt(self, mpk: Dict[str, Any], ct: Dict[str, Any], sk: Dict[str, Any]) -> GTElement:
        """
        Dec:
          prod_{i in I} e(ct1,pi(i), sk1,i)^gamma_i * prod_{i in I} e(ct2,pi(i), sk2,i)^gamma_i
        """
        msp: MSP = sk["msp"]
        ct_attrs = set(ct["attributes"])
        coeff_map = msp.solve_reconstruction_coefficients(ct_attrs)
        if coeff_map is None:
            raise ValueError("Ciphertext attributes do not satisfy key access policy!")

        term1_gt = self.group.gt ** 0
        term2_gt = self.group.gt ** 0

        for i, gamma_i in coeff_map.items():
            attr = msp.pi[i]
            pair1 = self.group.pair(ct["ct1"][attr], sk["sk1"][i]) ** gamma_i
            pair2 = self.group.pair(ct["ct2"][attr], sk["sk2"][i]) ** gamma_i
            term1_gt = term1_gt * pair1
            term2_gt = term2_gt * pair2

        return term1_gt * term2_gt
