
"""Integration tests for CLI operations and audit logging."""

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from vault.audit_log import verify_audit_log
from vault.cli import main


def test_cli_encrypt_and_decrypt_are_audited(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    original = tmp_path / "evidence.txt"
    encrypted = tmp_path / "evidence.sev"
    recovered = tmp_path / "recovered.txt"

    original.write_bytes(b"Digital forensic evidence")

    passwords = iter([
        "Test-Password-123!",
        "Test-Password-123!",
    ])
    monkeypatch.setattr(
        "vault.cli.getpass.getpass",
        lambda prompt: next(passwords),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["sev", "encrypt", str(original), str(encrypted)],
    )

    assert main() == 0

    passwords = iter(["Test-Password-123!"])
    monkeypatch.setattr(
        "vault.cli.getpass.getpass",
        lambda prompt: next(passwords),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["sev", "decrypt", str(encrypted), str(recovered)],
    )

    assert main() == 0
    assert recovered.read_bytes() == original.read_bytes()

    log = tmp_path / "reports" / "audit.jsonl"
    valid, count, _ = verify_audit_log(log)

    assert valid
    assert count == 2

    records = [
        json.loads(line)
        for line in log.read_text(encoding="utf-8").splitlines()
    ]

    assert [record["action"] for record in records] == [
        "encrypt",
        "decrypt",
    ]
    assert all(record["status"] == "success" for record in records)
    assert records[0]["input_sha256"] is not None
    assert records[0]["output_sha256"] is not None


def test_wrong_password_is_audited(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    original = tmp_path / "evidence.txt"
    encrypted = tmp_path / "evidence.sev"
    recovered = tmp_path / "recovered.txt"

    original.write_bytes(b"Evidence that must remain protected")

    passwords = iter([
        "Correct-Test-Password!",
        "Correct-Test-Password!",
    ])
    monkeypatch.setattr(
        "vault.cli.getpass.getpass",
        lambda prompt: next(passwords),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["sev", "encrypt", str(original), str(encrypted)],
    )

    assert main() == 0

    monkeypatch.setattr(
        "vault.cli.getpass.getpass",
        lambda prompt: "Wrong-Test-Password!",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["sev", "decrypt", str(encrypted), str(recovered)],
    )

    assert main() == 1
    assert not recovered.exists()

    log = tmp_path / "reports" / "audit.jsonl"
    valid, count, _ = verify_audit_log(log)

    assert valid
    assert count == 2

    records = [
        json.loads(line)
        for line in log.read_text(encoding="utf-8").splitlines()
    ]

    assert records[0]["status"] == "success"
    assert records[1]["action"] == "decrypt"
    assert records[1]["status"] == "failure"
    assert "Authentication failed" in records[1]["detail"]
