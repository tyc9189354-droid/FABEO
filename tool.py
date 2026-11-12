#!/usr/bin/env python3
"""
================================================================================
FABEO: Unified Tool & CLI API
Fast Attribute-Based Encryption with Optimal Security
================================================================================

This module provides high-level APIs for hybrid encryption (KEM + DEM):
  - Setup, KeyGen, Encrypt, Decrypt for CP-ABE, KP-ABE, and DFA KP-ABE.
  - Transparent serialization of keys, ciphertexts, and credentials.
  - End-to-end payload encryption with AES-authenticated mode.
"""

import os
import json
from typing import Dict, Any, List, Set, Tuple, Optional
from .core.pairing_group import PairingGroup, GTElement
from .core.msp import MSP, PolicyParser
from .core.dfa import DFA
from .core.dem import DEM
from .schemes.fabeo_cp import FabeoCP
from .schemes.fabeo_kp import FabeoKP
from .schemes.fabeo_dfa import FabeoDFA


class FabeoTool:
    """Unified API for FABEO ABE cryptosystem operations."""

    def __init__(self, curve_name: str = "BLS12-381"):
        self.group = PairingGroup(curve_name=curve_name)
        self.cp = FabeoCP(self.group)
        self.kp = FabeoKP(self.group)
        self.dfa = FabeoDFA(self.group)

    # --------------------------------------------------------------------------
    # CP-ABE (Ciphertext-Policy) Hybrid Encryption
    # --------------------------------------------------------------------------

    def cp_setup(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        return self.cp.setup()

    def cp_keygen(self, msk: Dict[str, Any], attributes: Set[str]) -> Dict[str, Any]:
        return self.cp.keygen(msk, attributes)

    def cp_encrypt_message(
        self, mpk: Dict[str, Any], policy_str: str, plaintext: bytes
    ) -> Dict[str, Any]:
        """Hybrid encryption: KEM encapsulated key + DEM symmetric payload."""
        ct, d = self.cp.encrypt(mpk, policy_str)
        payload = DEM.encrypt(d, plaintext)
        return {
            "scheme": "FABEO_CP",
            "policy": policy_str,
            "kem_ct": {
                "tau": ct["tau"],
                "ct1": self.group.serialize_element(ct["ct1"]),
                "ct2": [self.group.serialize_element(x) for x in ct["ct2"]],
                "ct3": [self.group.serialize_element(x) for x in ct["ct3"]],
            },
            "dem_payload": payload,
        }

    def cp_decrypt_message(
        self, mpk: Dict[str, Any], package: Dict[str, Any], sk: Dict[str, Any]
    ) -> bytes:
        """Hybrid decryption: recover KEM key + decrypt DEM payload."""
        policy_str = package["policy"]
        msp = MSP.from_policy_string(self.group, policy_str)
        kem_dict = package["kem_ct"]

        ct = {
            "msp": msp,
            "tau": kem_dict["tau"],
            "ct1": self.group.deserialize_element(kem_dict["ct1"]),
            "ct2": [self.group.deserialize_element(x) for x in kem_dict["ct2"]],
            "ct3": [self.group.deserialize_element(x) for x in kem_dict["ct3"]],
        }

        d = self.cp.decrypt(mpk, ct, sk)
        return DEM.decrypt(d, package["dem_payload"])

    # --------------------------------------------------------------------------
    # KP-ABE (Key-Policy) Hybrid Encryption
    # --------------------------------------------------------------------------

    def kp_setup(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        return self.kp.setup()

    def kp_keygen(self, msk: Dict[str, Any], policy_str: str) -> Dict[str, Any]:
        return self.kp.keygen(msk, policy_str)

    def kp_encrypt_message(
        self, mpk: Dict[str, Any], attributes: Set[str], plaintext: bytes
    ) -> Dict[str, Any]:
        ct, d = self.kp.encrypt(mpk, attributes)
        payload = DEM.encrypt(d, plaintext)
        return {
            "scheme": "FABEO_KP",
            "attributes": list(attributes),
            "kem_ct": {
                "ct1": {k: self.group.serialize_element(v) for k, v in ct["ct1"].items()},
                "ct2": self.group.serialize_element(ct["ct2"]),
            },
            "dem_payload": payload,
        }

    def kp_decrypt_message(
        self, mpk: Dict[str, Any], package: Dict[str, Any], sk: Dict[str, Any]
    ) -> bytes:
        kem_dict = package["kem_ct"]
        ct = {
            "attributes": package["attributes"],
            "ct1": {k: self.group.deserialize_element(v) for k, v in kem_dict["ct1"].items()},
            "ct2": self.group.deserialize_element(kem_dict["ct2"]),
        }
        d = self.kp.decrypt(mpk, ct, sk)
        return DEM.decrypt(d, package["dem_payload"])

    # --------------------------------------------------------------------------
    # DFA KP-ABE Hybrid Encryption
    # --------------------------------------------------------------------------

    def dfa_setup(self, alphabet: Set[str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        return self.dfa.setup(alphabet)

    def dfa_keygen(self, msk: Dict[str, Any], dfa: DFA) -> Dict[str, Any]:
        return self.dfa.keygen(msk, dfa)

    def dfa_encrypt_message(
        self, mpk: Dict[str, Any], word: str, plaintext: bytes
    ) -> Dict[str, Any]:
        ct, d = self.dfa.encrypt(mpk, list(word))
        payload = DEM.encrypt(d, plaintext)
        return {
            "scheme": "FABEO_DFA",
            "word": word,
            "kem_ct": {
                "ct0": self.group.serialize_element(ct["ct0"]),
                "ct1": self.group.serialize_element(ct["ct1"]),
                "ct2": {str(k): self.group.serialize_element(v) for k, v in ct["ct2"].items()},
                "ct3": {str(k): self.group.serialize_element(v) for k, v in ct["ct3"].items()},
                "ct4": self.group.serialize_element(ct["ct4"]),
            },
            "dem_payload": payload,
        }

    def dfa_decrypt_message(
        self, mpk: Dict[str, Any], package: Dict[str, Any], sk: Dict[str, Any]
    ) -> bytes:
        word = package["word"]
        kem_dict = package["kem_ct"]
        ct = {
            "x": list(word),
            "ct0": self.group.deserialize_element(kem_dict["ct0"]),
            "ct1": self.group.deserialize_element(kem_dict["ct1"]),
            "ct2": {int(k): self.group.deserialize_element(v) for k, v in kem_dict["ct2"].items()},
            "ct3": {int(k): self.group.deserialize_element(v) for k, v in kem_dict["ct3"].items()},
            "ct4": self.group.deserialize_element(kem_dict["ct4"]),
        }
        d = self.dfa.decrypt(mpk, ct, sk)
        return DEM.decrypt(d, package["dem_payload"])
