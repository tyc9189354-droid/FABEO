#!/usr/bin/env python3
"""
================================================================================
FABEO: Fast Attribute-Based Encryption with Optimal Security
Deterministic Finite Automata (DFA) Engine
================================================================================

This module implements:
  1. DFA representation (Q, Sigma, delta, F):
       - State space: [Q] = {1, 2, ..., Q}
       - Start state: 1
       - Accept states: F subset of [Q]
       - Transition function: delta(u, sigma) -> v in [Q]
  2. DFA simulation, execution tracer, and regular expression / pattern builder.
"""

from typing import List, Dict, Set, Tuple, Optional, Any


class DFA:
    """
    Deterministic Finite Automaton (Q, Sigma, delta, F).
    State space is indexed 1..Q. Start state is 1.
    """
    def __init__(
        self,
        num_states: int,
        alphabet: Set[str],
        transitions: Dict[Tuple[int, str], int],
        accept_states: Set[int],
    ):
        self.num_states = num_states
        self.alphabet = set(alphabet)
        self.transitions = transitions  # (state, symbol) -> next_state
        self.accept_states = set(accept_states)

        # Validate
        for (u, s), v in transitions.items():
            if u < 1 or u > num_states:
                raise ValueError(f"Source state {u} out of range [1, {num_states}]")
            if v < 1 or v > num_states:
                raise ValueError(f"Target state {v} out of range [1, {num_states}]")
            if s not in self.alphabet:
                raise ValueError(f"Symbol {s} not in alphabet {self.alphabet}")

        for f in self.accept_states:
            if f < 1 or f > num_states:
                raise ValueError(f"Accept state {f} out of range [1, {num_states}]")

    def delta(self, u: int, sigma: str) -> Optional[int]:
        return self.transitions.get((u, sigma))

    def accepts(self, x: List[str]) -> bool:
        """Evaluate input string x = [x1, ..., xl]. Returns True iff accepted."""
        curr = 1  # start state
        for sym in x:
            nxt = self.delta(curr, sym)
            if nxt is None:
                return False
            curr = nxt
        return curr in self.accept_states

    def get_execution_path(self, x: List[str]) -> Optional[Tuple[List[int], int]]:
        """
        Returns (state_sequence [u_1, ..., u_l], final_state)
        where u_1 = 1, u_{i+1} = delta(u_i, x_i) for i in [l-1],
        and final_state = delta(u_l, x_l) in F.
        Returns None if not accepted.
        """
        l = len(x)
        if l == 0:
            return None

        states = []
        curr = 1
        for i in range(l):
            states.append(curr)
            nxt = self.delta(curr, x[i])
            if nxt is None:
                return None
            curr = nxt

        final_state = curr
        if final_state not in self.accept_states:
            return None

        return states, final_state

    @classmethod
    def from_pattern_substring(cls, pattern: str, alphabet: Optional[Set[str]] = None) -> "DFA":
        """
        Construct a DFA that accepts strings containing `pattern` as a substring.
        Uses KMP failure function.
        """
        m = len(pattern)
        if m == 0:
            raise ValueError("Pattern cannot be empty")

        if alphabet is None:
            alphabet = set(pattern) | {"a", "b", "c", "0", "1"}

        num_states = m + 1
        accept_states = {num_states}
        transitions = {}

        # Build KMP transition table
        # states 1 .. m+1, where 1 is empty prefix, m+1 is matched
        for u in range(1, m + 1):
            curr_pref = pattern[: u - 1]
            for sym in alphabet:
                cand = curr_pref + sym
                # find longest prefix of pattern that is suffix of cand
                nxt_len = 0
                for k in range(min(len(cand), m), 0, -1):
                    if cand.endswith(pattern[:k]):
                        nxt_len = k
                        break
                transitions[(u, sym)] = nxt_len + 1

        # Final state is absorbing
        for sym in alphabet:
            transitions[(num_states, sym)] = num_states

        return cls(num_states, alphabet, transitions, accept_states)
