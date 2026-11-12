#!/usr/bin/env python3
"""
Unit tests for Monotone Span Program and Lewko-Waters Compiler
"""

import unittest
from FABEO.core.pairing_group import PairingGroup
from FABEO.core.msp import MSP, PolicyParser


class TestMSP(unittest.TestCase):
    def setUp(self):
        self.group = PairingGroup()

    def test_basic_and_or(self):
        policy = "(A AND B) OR C"
        msp = MSP.from_policy_string(self.group, policy)
        self.assertEqual(msp.tau, 1)

        # Satisfying: {A, B}
        sol1 = msp.solve_reconstruction_coefficients({"A", "B"})
        self.assertIsNotNone(sol1)

        # Satisfying: {C}
        sol2 = msp.solve_reconstruction_coefficients({"C"})
        self.assertIsNotNone(sol2)

        # Non-satisfying: {A}
        sol3 = msp.solve_reconstruction_coefficients({"A"})
        self.assertIsNone(sol3)

    def test_multi_use_attribute(self):
        policy = "(A AND B) OR (A AND C)"
        msp = MSP.from_policy_string(self.group, policy)
        self.assertEqual(msp.tau, 2)

        # Satisfying: {A, C}
        sol = msp.solve_reconstruction_coefficients({"A", "C"})
        self.assertIsNotNone(sol)

        # Non-satisfying: {B, C}
        sol_no = msp.solve_reconstruction_coefficients({"B", "C"})
        self.assertIsNone(sol_no)

    def test_threshold_gate(self):
        # 2 of (A, B, C)
        policy = "2 OF (A, B, C)"
        msp = MSP.from_policy_string(self.group, policy)

        sol_ab = msp.solve_reconstruction_coefficients({"A", "B"})
        self.assertIsNotNone(sol_ab)

        sol_ac = msp.solve_reconstruction_coefficients({"A", "C"})
        self.assertIsNotNone(sol_ac)

        sol_a = msp.solve_reconstruction_coefficients({"A"})
        self.assertIsNone(sol_a)


if __name__ == "__main__":
    unittest.main()
