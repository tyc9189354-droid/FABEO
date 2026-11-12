#!/usr/bin/env python3
"""
Unit tests for FABEO KP-ABE Scheme
"""

import unittest
from FABEO.core.pairing_group import PairingGroup
from FABEO.schemes.fabeo_kp import FabeoKP


class TestFabeoKP(unittest.TestCase):
    def setUp(self):
        self.group = PairingGroup()
        self.scheme = FabeoKP(self.group)
        self.mpk, self.msk = self.scheme.setup()

    def test_single_attribute(self):
        sk = self.scheme.keygen(self.msk, "ATTR1")

        ct_auth, d_enc = self.scheme.encrypt(self.mpk, {"ATTR1"})
        d_dec = self.scheme.decrypt(self.mpk, ct_auth, sk)
        self.assertEqual(d_enc, d_dec)

        ct_unauth, _ = self.scheme.encrypt(self.mpk, {"ATTR2"})
        with self.assertRaises(ValueError):
            self.scheme.decrypt(self.mpk, ct_unauth, sk)

    def test_multi_use_key_policy(self):
        policy = "(A AND B) OR (A AND C)"
        sk = self.scheme.keygen(self.msk, policy)

        # Ciphertext {A, C} satisfies
        ct1, d1 = self.scheme.encrypt(self.mpk, {"A", "C"})
        self.assertEqual(d1, self.scheme.decrypt(self.mpk, ct1, sk))

        # Ciphertext {A, B} satisfies
        ct2, d2 = self.scheme.encrypt(self.mpk, {"A", "B"})
        self.assertEqual(d2, self.scheme.decrypt(self.mpk, ct2, sk))

        # Ciphertext {B, C} rejects
        ct3, _ = self.scheme.encrypt(self.mpk, {"B", "C"})
        with self.assertRaises(ValueError):
            self.scheme.decrypt(self.mpk, ct3, sk)


if __name__ == "__main__":
    unittest.main()
