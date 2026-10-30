# Secure Evidence Vault

Secure Evidence Vault is a Python command-line application for encrypting and decrypting digital evidence files. I developed it to practise applied cryptography, file integrity checks, and basic forensic audit logging.

## What it does

- Encrypts files using AES-256-GCM.
- Derives encryption keys from passwords using Scrypt.
- Detects incorrect passwords and modified encrypted files.
- Refuses to overwrite existing output files.
- Records encryption and decryption operations in a JSONL audit log.
- Uses SHA-256 hashes to identify files and link audit entries.
- Includes automated tests for encryption, file handling, and audit-log integrity.

## Project structure

```text
SecureEvidenceVault/
├── examples/              # Sample evidence for testing
├── reports/               # Audit log output
├── src/vault/
│   ├── audit_log.py       # Audit records and hash-chain verification
│   ├── cli.py             # Command-line interface
│   ├── crypto_utils.py    # Encryption and decryption functions
│   └── file_vault.py      # File-level operations
├── tests/                 # Automated tests
├── README.md
├── requirements.txt
└── requirements-dev.txt
```

## Setup

Tested with Python 3.11 on Windows.

Open PowerShell in the project directory and run:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
$env:PYTHONPATH = "$PWD\src"
```

## Usage


The example file `examples/sample_evidence.txt` contains synthetic data.

Create the output directory before running the example:

```powershell
New-Item -ItemType Directory -Force -Path .\vault_data | Out-Null
```


**Encrypt a file:**

```powershell
.\.venv\Scripts\python.exe -m vault.cli encrypt .\examples\sample_evidence.txt .\vault_data\sample.sev
```

Enter a password and confirm it when prompted.

**Decrypt the file:**

```powershell
.\.venv\Scripts\python.exe -m vault.cli decrypt .\vault_data\sample.sev .\vault_data\recovered.txt
```

Enter the same password used for encryption.

**Verify the audit log:**

```powershell
.\.venv\Scripts\python.exe -c "from vault.audit_log import verify_audit_log; print(verify_audit_log('reports/audit.jsonl'))"
```

Run these commands from the project root so the audit log is written to the expected location.

## Tests

Run the test suite with:

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

The current suite has 20 passing tests, covering encryption and decryption, incorrect passwords, modified files, output-file handling, and audit-log verification.

I also tested the application with a sample file and compared the SHA-256 hashes of the original and recovered files. The hashes matched.

## Security limitations

This is a learning project, not a production forensic evidence management system.

The audit log uses a SHA-256 hash chain to detect modifications to recorded entries. However, someone able to rewrite the entire log could recalculate the chain. Stronger protection would require independently protected checkpoints or digital signatures.

The project does not currently provide user accounts, role-based access controls, hardware-backed key storage, or a complete forensic chain-of-custody system. It should not be used to store real sensitive evidence without further security work.
