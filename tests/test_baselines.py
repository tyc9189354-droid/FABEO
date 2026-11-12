#!/usr/bin/env python3
"""
Unit tests for Baseline Schemes (BSW CP, ABGW CP, ABGW KP)
"""

import unittest
from FABEO.core.pairing_group import PairingGroup
from FABEO.schemes.bsw_cp import BswCP
from FABEO.schemes.abgw_cp import AbgwCP
from FABEO.schemes.abgw_kp import AbgwKP


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


if __name__ == "__main__":
    unittest.main()
