
"""Password-protected file encryption for the evidence vault."""

import os
from pathlib import Path

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from vault.crypto_utils import encrypt_bytes, decrypt_bytes


MAGIC = b"SEV1"
SALT_SIZE = 16
KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from a password and random salt."""
    if not isinstance(password, str) or not password:
        raise ValueError("Password must not be empty.")

    kdf = Scrypt(
        salt=salt,
        length=KEY_SIZE,
        n=2**14,
        r=8,
        p=1,
    )

    return kdf.derive(password.encode("utf-8"))


def _write_new_file(path: Path, data: bytes) -> None:
    """Create a new file without overwriting an existing file."""
    created = False

    try:
        with path.open("xb") as output:
            created = True
            output.write(data)
    except Exception:
        if created:
            path.unlink(missing_ok=True)
        raise


def encrypt_file(
    input_path: Path,
    output_path: Path,
    password: str,
) -> None:
    """Encrypt a file using password-derived AES-256-GCM."""
    input_path = Path(input_path)
    output_path = Path(output_path)

    if input_path.resolve() == output_path.resolve():
        raise ValueError("Input and output paths must be different.")

    plaintext = input_path.read_bytes()

    salt = os.urandom(SALT_SIZE)
    key = _derive_key(password, salt)

    # Authenticate the file-format identifier and salt.
    header = MAGIC + salt

    encrypted_payload = encrypt_bytes(
        plaintext,
        key,
        associated_data=header,
    )

    # Format: magic + salt + nonce + ciphertext + authentication tag.
    _write_new_file(
        output_path,
        header + encrypted_payload,
    )


def decrypt_file(
    input_path: Path,
    output_path: Path,
    password: str,
) -> None:
    """Authenticate and decrypt an encrypted evidence file."""
    input_path = Path(input_path)
    output_path = Path(output_path)

    if input_path.resolve() == output_path.resolve():
        raise ValueError("Input and output paths must be different.")

    encrypted_file = input_path.read_bytes()

    # Reject files that do not use our vault format.
    if not encrypted_file.startswith(MAGIC):
        raise ValueError("Unrecognized evidence file format.")

    minimum_size = (
        len(MAGIC) + SALT_SIZE + NONCE_SIZE + TAG_SIZE
    )

    if len(encrypted_file) < minimum_size:
        raise ValueError("Encrypted evidence file is too short.")

    header_end = len(MAGIC) + SALT_SIZE

    header = encrypted_file[:header_end]
    salt = encrypted_file[len(MAGIC):header_end]
    encrypted_payload = encrypted_file[header_end:]

    key = _derive_key(password, salt)

    # Authentication must succeed before plaintext is written.
    plaintext = decrypt_bytes(
        encrypted_payload,
        key,
        associated_data=header,
    )

    # Never overwrite an existing output file.
    _write_new_file(output_path, plaintext)
