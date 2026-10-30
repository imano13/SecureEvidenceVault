
"""Authenticated encryption utilities for digital evidence."""

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEY_SIZE = 32       # 32 bytes = 256 bits
NONCE_SIZE = 12     # 96-bit nonce recommended for AES-GCM
TAG_SIZE = 16       # 128-bit authentication tag


def generate_key() -> bytes:
    """Generate a cryptographically secure AES-256 key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_bytes(
    plaintext: bytes,
    key: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    """Encrypt bytes and return nonce + ciphertext + authentication tag."""
    if len(key) != KEY_SIZE:
        raise ValueError("AES-256 requires a 32-byte key.")

    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(
        nonce,
        plaintext,
        associated_data,
    )

    # The nonce is not secret and must accompany the ciphertext.
    # The encryption key must be stored separately.
    return nonce + ciphertext


def decrypt_bytes(
    encrypted_data: bytes,
    key: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    """Decrypt data and reject invalid or modified ciphertext."""
    if len(key) != KEY_SIZE:
        raise ValueError("AES-256 requires a 32-byte key.")

    if len(encrypted_data) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Encrypted data is too short.")

    nonce = encrypted_data[:NONCE_SIZE]
    ciphertext = encrypted_data[NONCE_SIZE:]

    # InvalidTag is raised if the key, ciphertext, tag, or
    # associated data does not authenticate successfully.
    return AESGCM(key).decrypt(
        nonce,
        ciphertext,
        associated_data,
    )
