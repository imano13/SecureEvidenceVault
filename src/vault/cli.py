
"""Command-line interface for the Secure Evidence Vault."""

import argparse
import getpass
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag

from vault.audit_log import (
    DEFAULT_LOG,
    append_event,
    verify_audit_log,
)
from vault.file_vault import decrypt_file, encrypt_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Encrypt and decrypt digital evidence securely."
    )

    commands = parser.add_subparsers(
        dest="command",
        required=True,
    )

    encrypt_command = commands.add_parser(
        "encrypt",
        help="Encrypt an evidence file.",
    )
    encrypt_command.add_argument("input", type=Path)
    encrypt_command.add_argument("output", type=Path)

    decrypt_command = commands.add_parser(
        "decrypt",
        help="Decrypt an encrypted evidence file.",
    )
    decrypt_command.add_argument("input", type=Path)
    decrypt_command.add_argument("output", type=Path)

    return parser


def _record_failure(
    action: str,
    input_path: Path,
    output_path: Path,
    detail: str,
) -> None:
    """Record a failed operation without hiding its original error."""
    try:
        append_event(
            action=action,
            status="failure",
            input_path=input_path,
            output_path=output_path,
            detail=detail,
            log_path=DEFAULT_LOG,
        )
    except (OSError, ValueError) as error:
        print(
            f"Warning: failure could not be audited: {error}",
            file=sys.stderr,
        )


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # Fail closed if the existing audit log has been modified.
    valid, _, message = verify_audit_log(DEFAULT_LOG)

    if not valid:
        print(
            f"Error: audit log integrity check failed: {message}",
            file=sys.stderr,
        )
        return 1

    try:
        if args.command == "encrypt":
            password = getpass.getpass("Create vault password: ")
            confirmation = getpass.getpass("Confirm vault password: ")

            if password != confirmation:
                try:
                    append_event(
                        action="encrypt",
                        status="failure",
                        input_path=args.input,
                        output_path=args.output,
                        detail="Password confirmation mismatch",
                        log_path=DEFAULT_LOG,
                    )
                except (OSError, ValueError) as error:
                    print(
                        f"Error recording audit event: {error}",
                        file=sys.stderr,
                    )
                    return 1

                print(
                    "Error: passwords do not match.",
                    file=sys.stderr,
                )
                return 2

            encrypt_file(args.input, args.output, password)

        else:
            password = getpass.getpass("Vault password: ")
            decrypt_file(args.input, args.output, password)

    except InvalidTag:
        _record_failure(
            args.command,
            args.input,
            args.output,
            "Authentication failed: incorrect password or modified evidence",
        )
        print(
            "Error: authentication failed. Check the password "
            "and evidence integrity.",
            file=sys.stderr,
        )
        return 1

    except (OSError, ValueError) as error:
        _record_failure(
            args.command,
            args.input,
            args.output,
            str(error),
        )
        print(f"Error: {error}", file=sys.stderr)
        return 1

    # Record success only after the file operation succeeds.
    try:
        append_event(
            action=args.command,
            status="success",
            input_path=args.input,
            output_path=args.output,
            detail="Operation completed",
            log_path=DEFAULT_LOG,
        )
    except (OSError, ValueError) as error:
        print(
            "Error: the file operation completed, but its audit "
            f"record could not be written: {error}",
            file=sys.stderr,
        )
        return 1

    print(
        f"Evidence {args.command}ed successfully: {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
