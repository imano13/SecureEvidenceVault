
"""Tests for the tamper-evident audit log."""

import hashlib
import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from vault.audit_log import (
    append_event,
    verify_audit_log,
    GENESIS_HASH,
)


def test_missing_audit_log_is_valid():
    valid, count, message = verify_audit_log(
        Path("nonexistent_audit_test.jsonl")
    )

    assert valid
    assert count == 0
    assert "does not exist" in message


def test_events_form_a_valid_hash_chain(tmp_path):
    log = tmp_path / "audit.jsonl"
    source = tmp_path / "evidence.txt"
    encrypted = tmp_path / "evidence.sev"

    source.write_bytes(b"Sample evidence")
    encrypted.write_bytes(b"Encrypted sample")

    first = append_event(
        "encrypt", "success", source, encrypted, log_path=log
    )
    second = append_event(
        "decrypt", "success", encrypted, source, log_path=log
    )

    valid, count, message = verify_audit_log(log)

    assert valid
    assert count == 2
    assert message == "Audit log verified."
    assert first["previous_hash"] == GENESIS_HASH
    assert second["previous_hash"] == first["entry_hash"]
    assert first["input_sha256"] == hashlib.sha256(
        source.read_bytes()
    ).hexdigest()


def test_modified_event_is_detected(tmp_path):
    log = tmp_path / "audit.jsonl"

    append_event("encrypt", "success", log_path=log)

    record = json.loads(log.read_text(encoding="utf-8"))
    record["status"] = "modified"

    log.write_text(
        json.dumps(record) + "\n",
        encoding="utf-8",
    )

    valid, _, message = verify_audit_log(log)

    assert not valid
    assert "Hash mismatch" in message


def test_append_is_refused_after_tampering(tmp_path):
    log = tmp_path / "audit.jsonl"

    append_event("encrypt", "success", log_path=log)

    record = json.loads(log.read_text(encoding="utf-8"))
    record["action"] = "tampered"

    log.write_text(
        json.dumps(record) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Refusing to append"):
        append_event("decrypt", "success", log_path=log)
