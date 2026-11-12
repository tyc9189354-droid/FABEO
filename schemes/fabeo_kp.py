#!/usr/bin/env python3
"""
================================================================================
FABEO: Fast Attribute-Based Encryption with Optimal Security
Key-Policy Attribute-Based Encryption (KP-ABE)
Reference: Figure 1 (right) & Section 6.2
================================================================================
"""

from typing import Set, Dict, List, Tuple, Any, Optional
from ..core.pairing_group import PairingGroup, Zp, G1Element, G2Element, GTElement
from ..core.msp import MSP, PolicyParser
from .base_abe import BaseABE


class FabeoKP(BaseABE):
    """
    FABEO KP-ABE Scheme for Monotone Span Programs.
    Supports unbounded attribute universe and attribute multi-use.
    """

    def __init__(self, group: PairingGroup):
        super().__init__(group)

    def setup(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Setup(1^lambda):
          alpha <-$ Z_p
          mpk := (G, H, e(g1, g2)^alpha)
          msk := alpha
        """
        alpha = self.group.random()
        eg1g2_alpha = self.group.pair(self.group.g1, self.group.g2) ** alpha

        mpk = {
            "type": "FABEO_KP_MPK",
            "eg1g2_alpha": eg1g2_alpha,
        }
        msk = {
            "type": "FABEO_KP_MSK",
            "alpha": alpha,
        }
        return mpk, msk

    def keygen(self, msk: Dict[str, Any], policy_or_msp: Any) -> Dict[str, Any]:
        """
        KeyGen(msk, (M, pi)):
          r' <-$ Z_p^tau, v <-$ Z_p^(n2-1)
          sk1,j := g2^(r'[j]) for j in [tau]
          sk2,i := g1^(M_i (alpha || v)^T) * H(pi(i))^(r'[rho(i)]) for each row i in [n1]
          Output sk := ((sk1,j)_{j in [tau]}, (sk2,i)_{i in [n1]})
        """
        if isinstance(policy_or_msp, str):
            msp = MSP.from_policy_string(self.group, policy_or_msp)
        elif isinstance(policy_or_msp, MSP):
            msp = policy_or_msp
        else:
            raise TypeError("Expected policy string or MSP object")

        alpha = msk["alpha"]
        n1, n2 = msp.n1, msp.n2
        tau = msp.tau

        # r' in Z_p^tau
        r_prime = [self.group.random() for _ in range(tau)]
        # v in Z_p^(n2-1)
        v = [self.group.random() for _ in range(n2 - 1)]
        v_full = [alpha] + v

        # sk1,j = g2^(r'[j]) for j in [0..tau-1]
        sk1 = [self.group.g2 ** r_prime[j] for j in range(tau)]

        # sk2,i for each row i in [0..n1-1]
        sk2 = []
        p = self.group.order
        for i in range(n1):
            dot_val = 0
            for k in range(n2):
                if msp.matrix[i][k] != 0:
                    dot_val = (dot_val + msp.matrix[i][k] * int(v_full[k])) % p

            rho_i = msp.rho[i]
            r_prime_rho = r_prime[rho_i - 1]

            h_pi = self.group.hash_to_g1(msp.pi[i])
            term1 = self.group.g1 ** dot_val
            term2 = h_pi ** r_prime_rho
            sk2.append(term1 * term2)

        return {
            "type": "FABEO_KP_SK",
            "msp": msp,
            "tau": tau,
            "sk1": sk1,
            "sk2": sk2,
        }

    def encrypt(self, mpk: Dict[str, Any], attributes: Set[str]) -> Tuple[Dict[str, Any], GTElement]:
        """
        Enc(mpk, S subset of U):
          s <-$ Z_p
          ct1,u := H(u)^s for each u in S
          ct2 := g2^s
          Output ct := ((ct1,u)_{u in S}, ct2) and d := e(g1, g2)^(alpha * s)
        """
        s = self.group.random()

        ct1 = {}
        for attr in attributes:
            u_clean = attr.strip().upper()
            ct1[u_clean] = self.group.hash_to_g1(u_clean) ** s

        ct2 = self.group.g2 ** s
        d = mpk["eg1g2_alpha"] ** s

        ct = {
            "type": "FABEO_KP_CT",
            "attributes": list(ct1.keys()),
            "ct1": ct1,
            "ct2": ct2,
        }
        return ct, d

    def decrypt(self, mpk: Dict[str, Any], ct: Dict[str, Any], sk: Dict[str, Any]) -> GTElement:
        """
        Dec(mpk, S, (M, pi), ct, sk):
          If S satisfies (M, pi), find gamma_i such that sum_{i in I} gamma_i M_i = (1, 0, ..., 0).
          Reconstruct d = e( prod_{i in I} (sk2,i)^gamma_i, ct2 )
                         / prod_{j in [tau]} e( prod_{i in I, rho(i)=j} (ct1,pi(i))^gamma_i, sk1,j )
        """
        msp: MSP = sk["msp"]
        ct_attributes = set(ct["attributes"])

        # Check satisfaction
        coeff_map = msp.solve_reconstruction_coefficients(ct_attributes)
        if coeff_map is None:
            raise ValueError("Ciphertext attributes do not satisfy key access policy!")

        # Term 1: e( prod_{i in I} (sk2[i])^gamma_i, ct2 )
        acc_sk2 = self.group.g1 ** 0
        for i, gamma_i in coeff_map.items():
            acc_sk2 = acc_sk2 * (sk["sk2"][i] ** gamma_i)

        term1 = self.group.pair(acc_sk2, ct["ct2"])

        # Term 2: prod_{j=1}^tau e( prod_{i in I, rho(i)=j} (ct1[pi(i)])^gamma_i, sk1[j-1] )
        term2 = self.group.gt ** 0
        tau = sk["tau"]
        for j in range(1, tau + 1):
            rows_j = [i for i in coeff_map if msp.rho[i] == j]
            if not rows_j:
                continue

            acc_ct1 = self.group.g1 ** 0
            for i in rows_j:
                gamma_i = coeff_map[i]
                attr = msp.pi[i]
                acc_ct1 = acc_ct1 * (ct["ct1"][attr] ** gamma_i)

            e_j = self.group.pair(acc_ct1, sk["sk1"][j - 1])
            term2 = term2 * e_j

        d = term1 / term2
        return d
