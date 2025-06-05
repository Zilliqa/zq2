#!/usr/bin/env python3

import os
import secrets
import hashlib

class SecretKey:
    """A class to handle cryptographic key generation and management."""
    
    @staticmethod
    def new() -> 'SecretKey':
        """Generate a new random secret key."""
        # Generate 32 random bytes
        key_bytes = secrets.token_bytes(32)
        return SecretKey(key_bytes)
    
    @staticmethod
    def from_hex(hex_str: str) -> 'SecretKey':
        """Create a SecretKey from a hex string."""
        try:
            key_bytes = bytes.fromhex(hex_str)
            if len(key_bytes) != 32:
                raise ValueError("Key must be 32 bytes (64 hex characters)")
            return SecretKey(key_bytes)
        except ValueError as e:
            raise ValueError(f"Invalid hex string: {e}")
    
    def __init__(self, key_bytes: bytes):
        """Initialize with raw key bytes."""
        if len(key_bytes) != 32:
            raise ValueError("Key must be 32 bytes")
        self._key = key_bytes
    
    def to_hex(self) -> str:
        """Convert the key to a hex string."""
        return self._key.hex()
    
    def to_bytes(self) -> bytes:
        """Get the raw key bytes."""
        return self._key
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecretKey):
            return NotImplemented
        return self._key == other._key
    
    def __hash__(self) -> int:
        return hash(self._key) 