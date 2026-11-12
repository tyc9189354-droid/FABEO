#!/usr/bin/env python3
"""
================================================================================
FABEO: Fast Attribute-Based Encryption with Optimal Security
Data Encapsulation Mechanism (DEM) & Hybrid Public-Key Encryption
================================================================================

Implements key derivation (HKDF-SHA256) and authenticated symmetric encryption
(AES-GCM / HMAC-SHA256-CTR) to combine with ABE KEM into a full PKE scheme.
"""

import os
import hmac
import hashlib
import secrets
from typing import Tuple, Dict, Any
from .pairing_group import GTElement


def hkdf_extract_and_expand(salt: bytes, ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """Standard RFC 5869 HKDF-SHA256."""
    if not salt:
        salt = bytes([0] * 32)
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()

    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


class DEM:
    """Authenticated encryption for arbitrary plaintext payloads."""

    @staticmethod
    def derive_key(d: GTElement, info: bytes = b"FABEO-HYBRID-DEM-KEY") -> Tuple[bytes, bytes]:
        """Derive (enc_key, mac_key) from GT key encapsulation."""
        ikm = d.to_bytes(32)
        key_material = hkdf_extract_and_expand(salt=b"FABEO_DEM_SALT", ikm=ikm, info=info, length=64)
        return key_material[:32], key_material[32:]

    @classmethod
    def encrypt(cls, d: GTElement, plaintext: bytes) -> Dict[str, Any]:
        """Encrypt arbitrary bytes payload with authenticated encryption."""
        enc_key, mac_key = cls.derive_key(d)
        iv = secrets.token_bytes(16)

        # AES-CTR keystream generation via SHA-256 block expansion
        ciphertext = bytearray(len(plaintext))
        block_len = 32
        for idx, offset in enumerate(range(0, len(plaintext), block_len)):
            counter_bytes = idx.to_bytes(8, "big")
            stream_block = hmac.new(enc_key, iv + counter_bytes, hashlib.sha256).digest()
            chunk = plaintext[offset : offset + block_len]
            for b_i in range(len(chunk)):
                ciphertext[offset + b_i] = chunk[b_i] ^ stream_block[b_i]

        tag = hmac.new(mac_key, iv + bytes(ciphertext), hashlib.sha256).digest()
        return {
            "iv": iv.hex(),
            "ciphertext": bytes(ciphertext).hex(),
            "tag": tag.hex(),
        }

    @classmethod
    def decrypt(cls, d: GTElement, payload: Dict[str, Any]) -> bytes:
        """Decrypt and verify tag."""
        enc_key, mac_key = cls.derive_key(d)
        iv = bytes.fromhex(payload["iv"])
        ciphertext = bytes.fromhex(payload["ciphertext"])
        tag = bytes.fromhex(payload["tag"])

        expected_tag = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError("Decryption failed: Authentication tag verification error!")

        plaintext = bytearray(len(ciphertext))
        block_len = 32
        for idx, offset in enumerate(range(0, len(ciphertext), block_len)):
            counter_bytes = idx.to_bytes(8, "big")
            stream_block = hmac.new(enc_key, iv + counter_bytes, hashlib.sha256).digest()
            chunk = ciphertext[offset : offset + block_len]
            for b_i in range(len(chunk)):
                plaintext[offset + b_i] = chunk[b_i] ^ stream_block[b_i]

        return bytes(plaintext)
