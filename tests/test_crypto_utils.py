
"""Security tests for the evidence encryption module."""

import sys
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from vault.crypto_utils import (
    decrypt_bytes,
    encrypt_bytes,
    generate_key,
)


def test_encryption_round_trip():
    key = generate_key()
    original = b"Sample digital forensic evidence"

    encrypted = encrypt_bytes(original, key)

    assert encrypted != original
    assert decrypt_bytes(encrypted, key) == original


def test_empty_plaintext_round_trip():
    key = generate_key()

    encrypted = encrypt_bytes(b"", key)

    assert decrypt_bytes(encrypted, key) == b""


def test_tampered_ciphertext_is_rejected():
    key = generate_key()
    encrypted = bytearray(encrypt_bytes(b"Evidence", key))

    encrypted[-1] ^= 1

    with pytest.raises(InvalidTag):
        decrypt_bytes(bytes(encrypted), key)


def test_wrong_key_is_rejected():
    encrypted = encrypt_bytes(b"Confidential evidence", generate_key())

    with pytest.raises(InvalidTag):
        decrypt_bytes(encrypted, generate_key())


def test_wrong_associated_data_is_rejected():
    key = generate_key()
    encrypted = encrypt_bytes(
        b"Evidence",
        key,
        associated_data=b"case-001",
    )

    with pytest.raises(InvalidTag):
        decrypt_bytes(
            encrypted,
            key,
            associated_data=b"case-002",
        )


def test_truncated_encrypted_data_is_rejected():
    key = generate_key()

    with pytest.raises(ValueError, match="too short"):
        decrypt_bytes(b"too short", key)


def test_invalid_key_length_is_rejected():
    with pytest.raises(ValueError, match="32-byte key"):
        encrypt_bytes(b"Evidence", b"short")
