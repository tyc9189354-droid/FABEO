#!/usr/bin/env python3
"""
================================================================================
FABEO: Fast Attribute-Based Encryption with Optimal Security
Ciphertext-Policy Attribute-Based Encryption (CP-ABE)
Reference: Figure 1 (left) & Section 6.1
================================================================================
"""

from typing import Set, Dict, List, Tuple, Any, Optional
from ..core.pairing_group import PairingGroup, Zp, G1Element, G2Element, GTElement
from ..core.msp import MSP, PolicyParser
from .base_abe import BaseABE


class FabeoCP(BaseABE):
    """
    FABEO CP-ABE Scheme for Monotone Span Programs.
    Supports unbounded attribute universe and attribute multi-use.
    """
    RESERVED_ROOT = "__FABEO_CP_ROOT_ATTR__"

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
            "type": "FABEO_CP_MPK",
            "eg1g2_alpha": eg1g2_alpha,
        }
        msk = {
            "type": "FABEO_CP_MSK",
            "alpha": alpha,
        }
        return mpk, msk

    def keygen(self, msk: Dict[str, Any], attributes: Set[str]) -> Dict[str, Any]:
        """
        KeyGen(msk, S subset of U):
          r <-$ Z_p
          sk1 := g1^alpha * H(|U|+1)^r
          sk2,u := H(u)^r for each u in S
          sk3 := g2^r
          sk := (sk1, {sk2,u}_{u in S}, sk3)
        """
        alpha = msk["alpha"]
        r = self.group.random()

        h_root = self.group.hash_to_g1(self.RESERVED_ROOT)
        sk1 = (self.group.g1 ** alpha) * (h_root ** r)

        sk2 = {}
        for attr in attributes:
            u_clean = attr.strip().upper()
            sk2[u_clean] = self.group.hash_to_g1(u_clean) ** r

        sk3 = self.group.g2 ** r

        return {
            "type": "FABEO_CP_SK",
            "attributes": list(sk2.keys()),
            "sk1": sk1,
            "sk2": sk2,
            "sk3": sk3,
        }

    def encrypt(self, mpk: Dict[str, Any], policy_or_msp: Any) -> Tuple[Dict[str, Any], GTElement]:
        """
        Enc(mpk, (M, pi)):
          s1 <-$ Z_p, v <-$ Z_p^(n2-1), s' <-$ Z_p^tau
          ct1 := g2^s1
          ct2,j := g2^(s'[j]) for j in [tau]
          ct3,i := H(|U|+1)^(M_i (s1 || v)^T) * H(pi(i))^(s'[rho(i)])
          d := e(g1, g2)^(alpha * s1)
        """
        if isinstance(policy_or_msp, str):
            msp = MSP.from_policy_string(self.group, policy_or_msp)
        elif isinstance(policy_or_msp, MSP):
            msp = policy_or_msp
        else:
            raise TypeError("Expected policy string or MSP object")

        n1, n2 = msp.n1, msp.n2
        tau = msp.tau

        s1 = self.group.random()
        # v in Z_p^(n2-1)
        v = [self.group.random() for _ in range(n2 - 1)]
        # secret vector s = (s1 || v)
        s_vec = [s1] + v

        # s' in Z_p^tau (1-indexed in paper)
        s_prime = [self.group.random() for _ in range(tau)]

        ct1 = self.group.g2 ** s1

        # ct2,j for j in [1..tau]
        ct2 = [self.group.g2 ** s_prime[j] for j in range(tau)]

        h_root = self.group.hash_to_g1(self.RESERVED_ROOT)

        # ct3,i for each row i in [0..n1-1]
        ct3 = []
        p = self.group.order
        for i in range(n1):
            # Compute M_i * (s1 || v)^T mod p
            dot_val = 0
            for k in range(n2):
                if msp.matrix[i][k] != 0:
                    dot_val = (dot_val + msp.matrix[i][k] * int(s_vec[k])) % p

            # rho(i) is 1-indexed count
            rho_i = msp.rho[i]
            s_prime_rho = s_prime[rho_i - 1]

            h_pi = self.group.hash_to_g1(msp.pi[i])
            term1 = h_root ** dot_val
            term2 = h_pi ** s_prime_rho
            ct3.append(term1 * term2)

        # Encapsulated key d = e(g1, g2)^(alpha * s1)
        d = mpk["eg1g2_alpha"] ** s1

        ct = {
            "type": "FABEO_CP_CT",
            "msp": msp,
            "tau": tau,
            "ct1": ct1,
            "ct2": ct2,
            "ct3": ct3,
        }
        return ct, d

    def decrypt(self, mpk: Dict[str, Any], ct: Dict[str, Any], sk: Dict[str, Any]) -> GTElement:
        """
        Dec(mpk, (M, pi), S, ct, sk):
          If S satisfies (M, pi), find gamma_i such that sum_{i in I} gamma_i M_i = (1, 0, ..., 0).
          Reconstruct d = [ e(sk1, ct1) * prod_{j in [tau]} e( prod_{i in I, rho(i)=j} (sk2,pi(i))^gamma_i, ct2,j ) ]
                         / e( prod_{i in I} (ct3,i)^gamma_i, sk3 )
        """
        msp: MSP = ct["msp"]
        sk_attributes = set(sk["attributes"])

        # Check satisfaction and find gamma_i
        coeff_map = msp.solve_reconstruction_coefficients(sk_attributes)
        if coeff_map is None:
            raise ValueError("Attributes do not satisfy the ciphertext access policy!")

        # Term 1: e(sk1, ct1)
        term1 = self.group.pair(sk["sk1"], ct["ct1"])

        # Term 2: prod_{j=1}^tau e( prod_{i in I, rho(i)=j} sk2[pi(i)]^gamma_i, ct2[j-1] )
        term2 = self.group.gt ** 0  # identity in GT
        tau = ct["tau"]
        for j in range(1, tau + 1):
            # Collect i in I where rho(i) == j
            rows_j = [i for i in coeff_map if msp.rho[i] == j]
            if not rows_j:
                continue

            # Multi-exponentiation in G1
            acc_g1 = self.group.g1 ** 0
            for i in rows_j:
                gamma_i = coeff_map[i]
                attr = msp.pi[i]
                acc_g1 = acc_g1 * (sk["sk2"][attr] ** gamma_i)

            e_j = self.group.pair(acc_g1, ct["ct2"][j - 1])
            term2 = term2 * e_j

        # Term 3: e( prod_{i in I} ct3[i]^gamma_i, sk3 )
        acc_ct3 = self.group.g1 ** 0
        for i, gamma_i in coeff_map.items():
            acc_ct3 = acc_ct3 * (ct["ct3"][i] ** gamma_i)

        term3 = self.group.pair(acc_ct3, sk["sk3"])

        # d = (term1 * term2) / term3
        d = (term1 * term2) / term3
        return d
