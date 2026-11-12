#!/usr/bin/env python3
"""
Unit tests for Type-III Pairing Group
"""

import unittest
from FABEO.core.pairing_group import PairingGroup, Zp, G1Element, G2Element, GTElement


class TestPairingGroup(unittest.TestCase):
    def setUp(self):
        self.group = PairingGroup()

    def test_bilinearity(self):
        a = self.group.random()
        b = self.group.random()

        # e(g1^a, g2^b) == e(g1, g2)^(a*b)
        p = self.group.g1 ** a
        q = self.group.g2 ** b

        pair_ab = self.group.pair(p, q)
        base_pair = self.group.pair(self.group.g1, self.group.g2)
        expected = base_pair ** (a * b)

        self.assertEqual(pair_ab, expected)

    def test_hash_to_g1_deterministic(self):
        h1 = self.group.hash_to_g1("USER:ALICE")
        h2 = self.group.hash_to_g1("USER:ALICE")
        h3 = self.group.hash_to_g1("USER:BOB")

        self.assertEqual(h1, h2)
        self.assertNotEqual(h1, h3)

    def test_serialization(self):
        r = self.group.random()
        g1_elem = self.group.g1 ** r
        d = self.group.serialize_element(g1_elem)
        recovered = self.group.deserialize_element(d)
        self.assertEqual(g1_elem, recovered)


if __name__ == "__main__":
    unittest.main()
