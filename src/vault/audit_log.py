
"""Tamper-evident, hash-chained audit logging."""

import hashlib
import hmac
import json
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_LOG = Path("reports") / "audit.jsonl"
GENESIS_HASH = "0" * 64


def _canonical_json(record: dict) -> bytes:
    """Serialize a record deterministically before hashing."""
    return json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _file_sha256(path: str | Path | None) -> str | None:
    """Calculate a file's SHA-256 hash without loading it all into memory."""
    if path is None:
        return None

    try:
        candidate = Path(path)
        if not candidate.is_file():
            return None

        digest = hashlib.sha256()

        with candidate.open("rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                digest.update(chunk)

        return digest.hexdigest()

    except OSError:
        return None


def verify_audit_log(
    log_path: str | Path = DEFAULT_LOG,
) -> tuple[bool, int, str]:
    """Verify record integrity, sequence numbers, and hash links."""
    log_path = Path(log_path)

    if not log_path.exists():
        return True, 0, "Audit log does not exist yet."

    previous_hash = GENESIS_HASH
    count = 0

    required_fields = {
        "sequence",
        "timestamp",
        "action",
        "status",
        "input_file",
        "input_sha256",
        "output_file",
        "output_sha256",
        "detail",
        "previous_hash",
        "entry_hash",
    }

    try:
        with log_path.open("r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                if not line.strip():
                    return False, count, f"Empty line at line {line_number}."

                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    return False, count, f"Invalid JSON at line {line_number}."

                if not isinstance(record, dict):
                    return False, count, f"Invalid record at line {line_number}."

                if not required_fields.issubset(record):
                    return False, count, f"Missing fields at line {line_number}."

                if record["sequence"] != count + 1:
                    return False, count, f"Invalid sequence at line {line_number}."

                if record["previous_hash"] != previous_hash:
                    return False, count, f"Broken hash chain at line {line_number}."

                entry_hash = record["entry_hash"]
                if not isinstance(entry_hash, str):
                    return False, count, f"Invalid hash at line {line_number}."

                body = {
                    key: value
                    for key, value in record.items()
                    if key != "entry_hash"
                }

                expected_hash = hashlib.sha256(
                    _canonical_json(body)
                ).hexdigest()

                if not hmac.compare_digest(entry_hash, expected_hash):
                    return False, count, f"Hash mismatch at line {line_number}."

                previous_hash = entry_hash
                count += 1

    except OSError:
        return False, count, "Could not read the audit log."

    return True, count, "Audit log verified."


def append_event(
    action: str,
    status: str,
    input_path: str | Path | None = None,
    output_path: str | Path | None = None,
    detail: str | None = None,
    log_path: str | Path = DEFAULT_LOG,
) -> dict:
    """Append an event, refusing to extend an invalid existing log."""
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    valid, count, message = verify_audit_log(log_path)

    if not valid:
        raise ValueError(f"Refusing to append: {message}")

    previous_hash = GENESIS_HASH

    if count:
        with log_path.open("r", encoding="utf-8") as file:
            for line in file:
                last_record = json.loads(line)

        previous_hash = last_record["entry_hash"]

    record = {
        "sequence": count + 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "status": status,
        "input_file": Path(input_path).name if input_path is not None else None,
        "input_sha256": _file_sha256(input_path),
        "output_file": Path(output_path).name if output_path is not None else None,
        "output_sha256": _file_sha256(output_path),
        "detail": detail,
        "previous_hash": previous_hash,
    }

    record["entry_hash"] = hashlib.sha256(
        _canonical_json(record)
    ).hexdigest()

    with log_path.open("a", encoding="utf-8", newline="\n") as file:
        file.write(
            json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n"
        )

    return record
