#!/usr/bin/env python3
"""
================================================================================
FABEO: Fast Attribute-Based Encryption with Optimal Security
Monotone Span Program (MSP) and Lewko-Waters Policy Compiler
================================================================================

This module implements:
  1. Lexer and Parser for Boolean formulas with AND, OR, parentheses,
     and k-of-n threshold gates.
  2. The Lewko-Waters MSP generator (EUROCRYPT 2011) that produces
     an MSP matrix M in {0, 1, -1}^(n1 x n2) and mapping pi: [n1] -> U.
  3. Attribute multi-use parameter calculation:
       rho(i) = |{z <= i : pi(z) == pi(i)}|
       tau = max_i rho(i)
  4. Vector reconstruction solver over Z_p:
       Find gamma_i such that sum_{i in I} gamma_i * M_i = (1, 0, ..., 0).
"""

import re
from typing import List, Dict, Tuple, Optional, Set, Any
from .pairing_group import PairingGroup, Zp


class ASTNode:
    """Abstract Syntax Tree node for access policies."""
    pass


class LeafNode(ASTNode):
    def __init__(self, attribute: str):
        self.attribute = attribute.strip().upper()

    def __repr__(self):
        return f"Leaf({self.attribute})"


class GateNode(ASTNode):
    def __init__(self, op: str, children: List[ASTNode], threshold: Optional[int] = None):
        self.op = op.upper()  # 'AND', 'OR', 'THRESHOLD'
        self.children = children
        self.threshold = threshold  # for k-of-n threshold gates

    def __repr__(self):
        if self.op == "THRESHOLD":
            return f"Threshold({self.threshold}-of-{len(self.children)}, {self.children})"
        return f"{self.op}({self.children})"


class PolicyParser:
    """Parses Boolean policy strings into AST."""

    @staticmethod
    def tokenize(policy_str: str) -> List[str]:
        # Handle operators, parentheses, commas
        # Support AND, OR, OF, &, |, ()
        cleaned = re.sub(r"\s+", " ", policy_str.strip())
        pattern = r"(\(|\)|\bAND\b|\bOR\b|\bOF\b|&|\||,|[A-Za-z0-9_:\.\-]+)"
        tokens = re.findall(pattern, cleaned, re.IGNORECASE)
        res = []
        for t in tokens:
            t_clean = t.strip()
            if not t_clean:
                continue
            if t_clean in ("&", "AND", "and"):
                res.append("AND")
            elif t_clean in ("|", "OR", "or"):
                res.append("OR")
            elif t_clean in ("OF", "of"):
                res.append("OF")
            elif t_clean == ",":
                res.append(",")
            elif t_clean in ("(", ")"):
                res.append(t_clean)
            else:
                res.append(t_clean)
        return res

    def __init__(self, tokens: List[str]):
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> Optional[str]:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def consume(self, expected: Optional[str] = None) -> str:
        tok = self.peek()
        if tok is None:
            raise ValueError(f"Unexpected end of input, expected: {expected}")
        if expected and tok.upper() != expected.upper():
            raise ValueError(f"Expected '{expected}', got '{tok}' at token {self.pos}")
        self.pos += 1
        return tok

    def parse(self) -> ASTNode:
        node = self.parse_or()
        if self.pos < len(self.tokens):
            raise ValueError(f"Unexpected extra tokens starting at '{self.tokens[self.pos]}'")
        return node

    def parse_or(self) -> ASTNode:
        node = self.parse_and()
        while self.peek() == "OR":
            self.consume("OR")
            right = self.parse_and()
            node = GateNode("OR", [node, right])
        return node

    def parse_and(self) -> ASTNode:
        node = self.parse_primary()
        while self.peek() == "AND":
            self.consume("AND")
            right = self.parse_primary()
            node = GateNode("AND", [node, right])
        return node

    def parse_primary(self) -> ASTNode:
        tok = self.peek()
        if tok is None:
            raise ValueError("Unexpected end of expression")

        # Check for k OF (child1, child2, ...) threshold syntax
        if tok.isdigit() and self.pos + 1 < len(self.tokens) and self.tokens[self.pos + 1].upper() == "OF":
            k = int(self.consume())
            self.consume("OF")
            self.consume("(")
            children = [self.parse_or()]
            while self.peek() == ",":
                self.consume(",")
                children.append(self.parse_or())
            self.consume(")")
            return GateNode("THRESHOLD", children, threshold=k)

        if tok == "(":
            self.consume("(")
            node = self.parse_or()
            self.consume(")")
            return node

        # Leaf attribute
        attr = self.consume()
        return LeafNode(attr)

    @classmethod
    def parse_string(cls, policy_str: str) -> ASTNode:
        tokens = cls.tokenize(policy_str)
        if not tokens:
            raise ValueError("Empty access policy")
        return cls(tokens).parse()


class MSP:
    """
    Monotone Span Program: (M, pi) over Z_p.
    M: n1 rows x n2 cols (entries in Z_p, Lewko-Waters produces 0, 1, -1).
    pi: list of length n1 mapping each row i to an attribute string.
    """
    def __init__(self, group: PairingGroup, matrix: List[List[int]], pi: List[str]):
        self.group = group
        self.matrix = matrix  # n1 rows, n2 cols
        self.n1 = len(matrix)
        self.n2 = len(matrix[0]) if self.n1 > 0 else 0
        self.pi = [p.upper() for p in pi]

        # Calculate rho(i) and tau
        self.rho: List[int] = []
        counts: Dict[str, int] = {}
        for attr in self.pi:
            counts[attr] = counts.get(attr, 0) + 1
            self.rho.append(counts[attr])

        self.tau = max(self.rho) if self.rho else 1

    @classmethod
    def from_ast(cls, group: PairingGroup, ast: ASTNode) -> "MSP":
        """
        Lewko-Waters MSP Generation algorithm (EUROCRYPT 2011).
        Converts policy AST into MSP matrix M and attribute list pi.
        """
        c = 1  # global vector length counter
        root_vec = [1]
        leaves: List[Tuple[str, List[int]]] = []

        def traverse(node: ASTNode, vec: List[int]):
            nonlocal c
            # Pad current vector to current length c
            v_curr = vec + [0] * (c - len(vec))

            if isinstance(node, LeafNode):
                leaves.append((node.attribute, v_curr))
                return

            if isinstance(node, GateNode):
                if node.op == "OR":
                    for child in node.children:
                        traverse(child, v_curr)

                elif node.op == "AND":
                    # AND gate: child 1 gets (v || 1), child 2 gets (0 || -1)
                    # Notice: (v || 1) + (0 || -1) = (v || 0)
                    c += 1
                    child1_vec = v_curr + [1]
                    child2_vec = [0] * (c - 1) + [-1]
                    traverse(node.children[0], child1_vec)
                    traverse(node.children[1], child2_vec)

                elif node.op == "THRESHOLD":
                    # Threshold k-of-n using Shamir secret sharing polynomial representation
                    k = node.threshold if node.threshold else len(node.children)
                    n = len(node.children)
                    if k == 1:
                        # Equivalent to OR
                        for child in node.children:
                            traverse(child, v_curr)
                    elif k == n:
                        # Multi-input AND
                        curr_v = v_curr
                        for idx, child in enumerate(node.children):
                            if idx == n - 1:
                                traverse(child, curr_v)
                            else:
                                c += 1
                                c_v = [0] * (c - 1) + [-1]
                                curr_v = curr_v + [1]
                                traverse(child, c_v)
                    else:
                        # k-of-n: polynomial shares
                        # Secret is parent vector. Polynomial q(x) of degree k-1:
                        # q(0) = v_curr, q(x) = v_curr + sum_{j=1}^{k-1} a_j * x^j
                        # Each coefficient a_j adds a new column coordinate
                        base_c = c
                        new_cols = k - 1
                        c += new_cols
                        for i, child in enumerate(node.children, start=1):
                            # child share at x = i: v_curr + sum_{j=1}^{k-1} (i^j) * coord_j
                            share_vec = v_curr + [pow(i, j, group.order) for j in range(1, k)]
                            traverse(child, share_vec)

        traverse(ast, root_vec)

        # Pad all leaf vectors with trailing zeros to final length c
        matrix = []
        pi = []
        for attr, vec in leaves:
            padded = vec + [0] * (c - len(vec))
            matrix.append(padded)
            pi.append(attr)

        return cls(group, matrix, pi)

    @classmethod
    def from_policy_string(cls, group: PairingGroup, policy_str: str) -> "MSP":
        ast = PolicyParser.parse_string(policy_str)
        return cls.from_ast(group, ast)

    def solve_reconstruction_coefficients(self, attributes: Set[str]) -> Optional[Dict[int, int]]:
        """
        Find reconstruction coefficients gamma_i in Z_p for i in I such that:
          sum_{i in I} gamma_i * M_i = (1, 0, ..., 0)
        Returns dict mapping row index i -> gamma_i (mod p), or None if unsatisfiable.
        """
        upper_attrs = {a.upper() for a in attributes}
        I = [i for i, attr in enumerate(self.pi) if attr in upper_attrs]
        if not I:
            return None

        p = self.group.order
        num_rows = len(I)
        num_cols = self.n2

        # Linear system: sum_{k=0}^{num_rows-1} gamma_k * M[I[k]][j] = target[j]
        # Augmented matrix [A^T | target]: num_cols equations in num_rows variables
        # A_T[j][k] = M[I[k]][j]
        target = [1] + [0] * (num_cols - 1)
        aug = [[self.matrix[I[k]][j] % p for k in range(num_rows)] + [target[j] % p] for j in range(num_cols)]

        # Gaussian elimination over Z_p
        lead = 0
        pivot_rows = {}
        for r in range(num_cols):
            if lead >= num_rows:
                break
            # Find pivot in column lead
            pivot = None
            for i in range(r, num_cols):
                if aug[i][lead] != 0:
                    pivot = i
                    break
            if pivot is None:
                continue

            aug[r], aug[pivot] = aug[pivot], aug[r]
            inv_piv = pow(aug[r][lead], -1, p)
            aug[r] = [(val * inv_piv) % p for val in aug[r]]

            for i in range(num_cols):
                if i != r and aug[i][lead] != 0:
                    factor = aug[i][lead]
                    aug[i] = [(aug[i][c_idx] - factor * aug[r][c_idx]) % p for c_idx in range(num_rows + 1)]

            pivot_rows[lead] = r
            lead += 1

        # Check consistency for rows r that have zero on LHS
        for r in range(num_cols):
            lhs_zeros = all(aug[r][c_idx] == 0 for c_idx in range(num_rows))
            if lhs_zeros and aug[r][-1] != 0:
                return None  # Inconsistent: 0 = non-zero

        # Extract solution
        gamma_sol = [0] * num_rows
        for col_idx, r_idx in pivot_rows.items():
            gamma_sol[col_idx] = aug[r_idx][-1] % p

        # Verify solution
        recon = [0] * num_cols
        for k in range(num_rows):
            if gamma_sol[k] != 0:
                row_vec = self.matrix[I[k]]
                for j in range(num_cols):
                    recon[j] = (recon[j] + gamma_sol[k] * row_vec[j]) % p

        if recon[0] != 1 or any(v != 0 for v in recon[1:]):
            return None

        return {I[k]: gamma_sol[k] for k in range(num_rows) if gamma_sol[k] != 0}
