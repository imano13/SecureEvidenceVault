
"""Tests for password-protected evidence files."""

import sys
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from vault.file_vault import encrypt_file, decrypt_file


def test_file_encryption_round_trip(tmp_path):
    original = tmp_path / "evidence.txt"
    encrypted = tmp_path / "evidence.sev"
    recovered = tmp_path / "recovered.txt"

    original.write_bytes(b"Digital forensic evidence")
    password = "Example-Strong-Password-2026!"

    encrypt_file(original, encrypted, password)
    decrypt_file(encrypted, recovered, password)

    assert encrypted.read_bytes() != original.read_bytes()
    assert recovered.read_bytes() == original.read_bytes()


def test_empty_file_round_trip(tmp_path):
    original = tmp_path / "empty.bin"
    encrypted = tmp_path / "empty.sev"
    recovered = tmp_path / "recovered.bin"

    original.write_bytes(b"")

    encrypt_file(original, encrypted, "Strong-Test-Password!")
    decrypt_file(encrypted, recovered, "Strong-Test-Password!")

    assert recovered.read_bytes() == b""


def test_wrong_password_is_rejected(tmp_path):
    original = tmp_path / "evidence.txt"
    encrypted = tmp_path / "evidence.sev"
    recovered = tmp_path / "recovered.txt"

    original.write_bytes(b"Sensitive evidence")
    encrypt_file(original, encrypted, "Correct-Password!")

    with pytest.raises(InvalidTag):
        decrypt_file(encrypted, recovered, "Wrong-Password!")

    assert not recovered.exists()


def test_tampered_file_is_rejected(tmp_path):
    original = tmp_path / "evidence.txt"
    encrypted = tmp_path / "evidence.sev"
    recovered = tmp_path / "recovered.txt"

    original.write_bytes(b"Evidence to protect")
    encrypt_file(original, encrypted, "Strong-Password!")

    tampered = bytearray(encrypted.read_bytes())
    tampered[-1] ^= 1
    encrypted.write_bytes(tampered)

    with pytest.raises(InvalidTag):
        decrypt_file(encrypted, recovered, "Strong-Password!")

    assert not recovered.exists()


def test_invalid_file_format_is_rejected(tmp_path):
    encrypted = tmp_path / "invalid.sev"
    recovered = tmp_path / "recovered.txt"

    encrypted.write_bytes(b"NOT_A_VALID_VAULT_FILE")

    with pytest.raises(ValueError, match="Unrecognized"):
        decrypt_file(encrypted, recovered, "Strong-Password!")

    assert not recovered.exists()


def test_existing_output_is_never_overwritten(tmp_path):
    original = tmp_path / "evidence.txt"
    encrypted = tmp_path / "evidence.sev"

    original.write_bytes(b"Original evidence")
    encrypted.write_bytes(b"Do not overwrite this")

    with pytest.raises(FileExistsError):
        encrypt_file(original, encrypted, "Strong-Password!")

    assert encrypted.read_bytes() == b"Do not overwrite this"


def test_each_encryption_uses_a_different_salt_and_nonce(tmp_path):
    original = tmp_path / "evidence.txt"
    first = tmp_path / "first.sev"
    second = tmp_path / "second.sev"

    original.write_bytes(b"Same evidence")
    password = "Strong-Password!"

    encrypt_file(original, first, password)
    encrypt_file(original, second, password)

    first_data = first.read_bytes()
    second_data = second.read_bytes()

    assert first_data[:20] != second_data[:20]
    assert first_data != second_data
