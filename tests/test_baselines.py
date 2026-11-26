#!/usr/bin/env python3
"""
Unit tests for Baseline Schemes:
- BSW CP-ABE (Bethencourt et al. 2007)
- ABGW CP-ABE & KP-ABE (Ambrona et al. 2017)
- FAME / AC17 CP-ABE & KP-ABE (Agrawal & Chase 2017)
- Waters 2012 DFA (Waters 2012)
"""

import unittest
from FABEO.core.pairing_group import PairingGroup
from FABEO.core.dfa import DFA
from FABEO.schemes.bsw_cp import BswCP
from FABEO.schemes.abgw_cp import AbgwCP
from FABEO.schemes.abgw_kp import AbgwKP
from FABEO.schemes.fame_cp import FameCP
from FABEO.schemes.fame_kp import FameKP
from FABEO.schemes.waters_dfa import WatersDFA


class TestBaselines(unittest.TestCase):
    def setUp(self):
        self.group = PairingGroup()

    def test_bsw_cp(self):
        scheme = BswCP(self.group)
        mpk, msk = scheme.setup()
        ct, d_enc = scheme.encrypt(mpk, "(A AND B) OR C")

        sk_ab = scheme.keygen(msk, {"A", "B"})
        self.assertEqual(d_enc, scheme.decrypt(mpk, ct, sk_ab))

        sk_c = scheme.keygen(msk, {"C"})
        self.assertEqual(d_enc, scheme.decrypt(mpk, ct, sk_c))

        sk_no = scheme.keygen(msk, {"A"})
        with self.assertRaises(ValueError):
            scheme.decrypt(mpk, ct, sk_no)

    def test_abgw_cp(self):
        scheme = AbgwCP(self.group)
        mpk, msk = scheme.setup()
        ct, d_enc = scheme.encrypt(mpk, "A AND B")

        sk_ab = scheme.keygen(msk, {"A", "B"})
        self.assertEqual(d_enc, scheme.decrypt(mpk, ct, sk_ab))

        sk_a = scheme.keygen(msk, {"A"})
        with self.assertRaises(ValueError):
            scheme.decrypt(mpk, ct, sk_a)

    def test_abgw_kp(self):
        scheme = AbgwKP(self.group)
        mpk, msk = scheme.setup()
        sk = scheme.keygen(msk, "A AND B")

        ct_ab, d_enc = scheme.encrypt(mpk, {"A", "B"})
        self.assertEqual(d_enc, scheme.decrypt(mpk, ct_ab, sk))

        ct_a, _ = scheme.encrypt(mpk, {"A"})
        with self.assertRaises(ValueError):
            scheme.decrypt(mpk, ct_a, sk)

    def test_fame_cp(self):
        scheme = FameCP(self.group)
        mpk, msk = scheme.setup()
        ct, d_enc = scheme.encrypt(mpk, "A AND B")

        sk_ab = scheme.keygen(msk, {"A", "B"})
        self.assertEqual(d_enc, scheme.decrypt(mpk, ct, sk_ab))

        sk_a = scheme.keygen(msk, {"A"})
        with self.assertRaises(ValueError):
            scheme.decrypt(mpk, ct, sk_a)

    def test_fame_kp(self):
        scheme = FameKP(self.group)
        mpk, msk = scheme.setup()
        sk = scheme.keygen(msk, "A AND B")

        ct_ab, d_enc = scheme.encrypt(mpk, {"A", "B"})
        self.assertEqual(d_enc, scheme.decrypt(mpk, ct_ab, sk))

        ct_a, _ = scheme.encrypt(mpk, {"A"})
        with self.assertRaises(ValueError):
            scheme.decrypt(mpk, ct_a, sk)

    def test_waters_dfa(self):
        scheme = WatersDFA(self.group)
        alphabet = {"a", "b"}
        dfa = DFA.from_pattern_substring("ab", alphabet)

        mpk, msk = scheme.setup(alphabet)
        sk = scheme.keygen(msk, dfa)

        x_acc = ["b", "a", "b", "a"]
        ct, d_enc = scheme.encrypt(mpk, x_acc)
        self.assertEqual(d_enc, scheme.decrypt(mpk, ct, sk))

        x_rej = ["b", "a", "a"]
        ct_rej, _ = scheme.encrypt(mpk, x_rej)
        with self.assertRaises(ValueError):
            scheme.decrypt(mpk, ct_rej, sk)


if __name__ == "__main__":
    unittest.main()
