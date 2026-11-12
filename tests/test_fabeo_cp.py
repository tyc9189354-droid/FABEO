#!/usr/bin/env python3
"""
Unit tests for FABEO CP-ABE Scheme
"""

import unittest
from FABEO.core.pairing_group import PairingGroup
from FABEO.schemes.fabeo_cp import FabeoCP


class TestFabeoCP(unittest.TestCase):
    def setUp(self):
        self.group = PairingGroup()
        self.scheme = FabeoCP(self.group)
        self.mpk, self.msk = self.scheme.setup()

    def test_single_attribute(self):
        policy = "ATTR1"
        ct, d_enc = self.scheme.encrypt(self.mpk, policy)

        sk_auth = self.scheme.keygen(self.msk, {"ATTR1"})
        d_dec = self.scheme.decrypt(self.mpk, ct, sk_auth)
        self.assertEqual(d_enc, d_dec)

        sk_unauth = self.scheme.keygen(self.msk, {"ATTR2"})
        with self.assertRaises(ValueError):
            self.scheme.decrypt(self.mpk, ct, sk_unauth)

    def test_complex_formula_and_multi_use(self):
        policy = "((A AND B) OR (A AND C)) AND (D OR E)"
        ct, d_enc = self.scheme.encrypt(self.mpk, policy)

        # Satisfying: {A, B, D}
        sk1 = self.scheme.keygen(self.msk, {"A", "B", "D"})
        self.assertEqual(d_enc, self.scheme.decrypt(self.mpk, ct, sk1))

        # Satisfying: {A, C, E}
        sk2 = self.scheme.keygen(self.msk, {"A", "C", "E"})
        self.assertEqual(d_enc, self.scheme.decrypt(self.mpk, ct, sk2))

        # Non-satisfying: {B, C, D, E} (missing A)
        sk_no_a = self.scheme.keygen(self.msk, {"B", "C", "D", "E"})
        with self.assertRaises(ValueError):
            self.scheme.decrypt(self.mpk, ct, sk_no_a)

        # Non-satisfying: {A, B} (missing D/E)
        sk_no_de = self.scheme.keygen(self.msk, {"A", "B"})
        with self.assertRaises(ValueError):
            self.scheme.decrypt(self.mpk, ct, sk_no_de)


if __name__ == "__main__":
    unittest.main()
