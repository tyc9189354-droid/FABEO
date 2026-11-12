#!/usr/bin/env python3
"""
================================================================================
FABEO: Base ABE Interface
================================================================================
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Tuple
from ..core.pairing_group import PairingGroup, GTElement


class BaseABE(ABC):
    """Abstract Base Class for Attribute-Based Encryption Schemes."""

    def __init__(self, group: PairingGroup):
        self.group = group

    @abstractmethod
    def setup(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Output (mpk, msk)."""
        pass

    @abstractmethod
    def keygen(self, msk: Dict[str, Any], predicate: Any) -> Dict[str, Any]:
        """Generate secret key sk."""
        pass

    @abstractmethod
    def encrypt(self, mpk: Dict[str, Any], policy_or_attrs: Any) -> Tuple[Dict[str, Any], GTElement]:
        """Output (ciphertext ct, encapsulated key d)."""
        pass

    @abstractmethod
    def decrypt(self, mpk: Dict[str, Any], ct: Dict[str, Any], sk: Dict[str, Any], **kwargs) -> GTElement:
        """Decrypt ciphertext and recover encapsulated key d."""
        pass
