#!/usr/bin/env python3
"""
Unit tests for FABEO DFA KP-ABE Scheme
"""

import unittest
from FABEO.core.pairing_group import PairingGroup
from FABEO.core.dfa import DFA
from FABEO.schemes.fabeo_dfa import FabeoDFA


class TestFabeoDFA(unittest.TestCase):
    def setUp(self):
        self.group = PairingGroup()
        self.scheme = FabeoDFA(self.group)
        self.alphabet = {"0", "1"}
        self.mpk, self.msk = self.scheme.setup(self.alphabet)

    def test_dfa_substring_pattern(self):
        # Recognizes any string containing substring '101'
        dfa = DFA.from_pattern_substring("101", self.alphabet)
        sk = self.scheme.keygen(self.msk, dfa)

        # Valid string: "001010"
        x_valid = list("001010")
        ct_valid, d_enc = self.scheme.encrypt(self.mpk, x_valid)
        d_dec = self.scheme.decrypt(self.mpk, ct_valid, sk)
        self.assertEqual(d_enc, d_dec)

        # Invalid string: "000000"
        x_invalid = list("000000")
        ct_invalid, _ = self.scheme.encrypt(self.mpk, x_invalid)
        with self.assertRaises(ValueError):
            self.scheme.decrypt(self.mpk, ct_invalid, sk)


if __name__ == "__main__":
    unittest.main()
