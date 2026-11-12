#!/usr/bin/env python3
"""
================================================================================
Baseline: ABGW CP-ABE Scheme (Ambrona et al., ACM CCS 2017)
Specified in Appendix C of the FABEO paper
================================================================================
"""

from typing import Set, Dict, List, Tuple, Any
from ..core.pairing_group import PairingGroup, Zp, G1Element, G2Element, GTElement
from ..core.msp import MSP
from .base_abe import BaseABE


class AbgwCP(BaseABE):
    """
    ABGW CP-ABE Scheme.
    Uses rational function exponents and requires I + 2 pairings for decryption.
    """

    def __init__(self, group: PairingGroup):
        super().__init__(group)

    def setup(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Setup(1^lambda):
          alpha <-$ Z_p, b <-$ Z_p^4
          mpk := (G, (g1^(b[j]))_{j in [1..4]}, e(g1, g2)^alpha)
          msk := (alpha, b)
        """
        alpha = self.group.random()
        b = [self.group.random() for _ in range(4)]  # b[0]..b[3] corresponding to b[1]..b[4]

        g1_b = [self.group.g1 ** b[j] for j in range(4)]
        eg1g2_alpha = self.group.pair(self.group.g1, self.group.g2) ** alpha

        mpk = {
            "type": "ABGW_CP_MPK",
            "g1_b": g1_b,
            "eg1g2_alpha": eg1g2_alpha,
        }
        msk = {
            "type": "ABGW_CP_MSK",
            "alpha": alpha,
            "b": b,
        }
        return mpk, msk

    def keygen(self, msk: Dict[str, Any], attributes: Set[str]) -> Dict[str, Any]:
        """
        KeyGen(msk, S):
          r <-$ Z_p
          sk1 := g2^(alpha - b[4]*r)
          sk2 := g2^r
          sk3,u := g2^( (r * b[3]) / (b[1] + u * b[2]) )
        """
        alpha = msk["alpha"]
        b = msk["b"]
        r = self.group.random()
        p = self.group.order

        sk1 = self.group.g2 ** (alpha - (b[3] * r))
        sk2 = self.group.g2 ** r

        sk3 = {}
        for attr in attributes:
            u_clean = attr.strip().upper()
            u_val = int.from_bytes(self.group.hash_to_g1(u_clean).to_bytes(32), "big") % p
            denom = (int(b[0]) + u_val * int(b[1])) % p
            if denom == 0:
                denom = 1
            inv_denom = pow(denom, -1, p)
            exp_u = (int(r) * int(b[2]) * inv_denom) % p
            sk3[u_clean] = self.group.g2 ** exp_u

        return {
            "type": "ABGW_CP_SK",
            "attributes": list(sk3.keys()),
            "sk1": sk1,
            "sk2": sk2,
            "sk3": sk3,
        }

    def encrypt(self, mpk: Dict[str, Any], policy_or_msp: Any) -> Tuple[Dict[str, Any], GTElement]:
        """
        Enc(mpk, (M, pi)):
          s1, s' in Z_p^n1, v in Z_p^(n2-1). mu_i := M_i (s1 || v)^T
          ct1,i := g1^mu_i
          ct2,i := g1^(-b[3]*s'[i]) * g1^(b[4]*mu_i)
          ct3,i := (g1^b[1] * (g1^b[2])^pi(i))^s'[i]
        """
        if isinstance(policy_or_msp, str):
            msp = MSP.from_policy_string(self.group, policy_or_msp)
        else:
            msp = policy_or_msp

        n1, n2 = msp.n1, msp.n2
        s1 = self.group.random()
        v = [self.group.random() for _ in range(n2 - 1)]
        s_vec = [s1] + v
        s_prime = [self.group.random() for _ in range(n1)]

        g1_b = mpk["g1_b"]
        ct1 = []
        ct2 = []
        ct3 = []
        p = self.group.order

        for i in range(n1):
            mu_i = 0
            for k in range(n2):
                if msp.matrix[i][k] != 0:
                    mu_i = (mu_i + msp.matrix[i][k] * int(s_vec[k])) % p

            ct1.append(self.group.g1 ** mu_i)

            term_b3 = g1_b[2] ** (-s_prime[i])
            term_b4 = g1_b[3] ** mu_i
            ct2.append(term_b3 * term_b4)

            u_clean = msp.pi[i]
            u_val = int.from_bytes(self.group.hash_to_g1(u_clean).to_bytes(32), "big") % p
            base3 = g1_b[0] * (g1_b[1] ** u_val)
            ct3.append(base3 ** s_prime[i])

        d = mpk["eg1g2_alpha"] ** s1
        ct = {
            "type": "ABGW_CP_CT",
            "msp": msp,
            "ct1": ct1,
            "ct2": ct2,
            "ct3": ct3,
        }
        return ct, d

    def decrypt(self, mpk: Dict[str, Any], ct: Dict[str, Any], sk: Dict[str, Any]) -> GTElement:
        """
        Dec:
          e( prod ct1,i^gamma_i, sk1 ) * e( prod ct2,i^gamma_i, sk2 ) * prod e(ct3,i, sk3,pi(i))^gamma_i
        """
        msp: MSP = ct["msp"]
        sk_attrs = set(sk["attributes"])
        coeff_map = msp.solve_reconstruction_coefficients(sk_attrs)
        if coeff_map is None:
            raise ValueError("Attributes do not satisfy access policy!")

        acc1 = self.group.g1 ** 0
        acc2 = self.group.g1 ** 0
        for i, gamma_i in coeff_map.items():
            acc1 = acc1 * (ct["ct1"][i] ** gamma_i)
            acc2 = acc2 * (ct["ct2"][i] ** gamma_i)

        t1 = self.group.pair(acc1, sk["sk1"])
        t2 = self.group.pair(acc2, sk["sk2"])

        t3 = self.group.gt ** 0
        for i, gamma_i in coeff_map.items():
            attr = msp.pi[i]
            p_i = self.group.pair(ct["ct3"][i], sk["sk3"][attr]) ** gamma_i
            t3 = t3 * p_i

        return t1 * t2 * t3
