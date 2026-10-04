from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path


def cmd_tokenize(args: argparse.Namespace) -> None:
    try:
        import tomllib  # type: ignore[import-not-found]  # stdlib 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[import-not-found]  # backport 3.10
        except ImportError:
            print(
                "Error: TOML config requires 'tomli' on Python < 3.11. "
                "Install with: pip install 'tokenvault[cli]'",
                file=sys.stderr,
            )
            sys.exit(1)
    from tokenvault.config import VaultConfig
    from tokenvault.fields.base import FieldType, PIIField
    from tokenvault.keys.env import EnvKeyStore
    from tokenvault.tokenizers.hmac_sha256 import HMACTokenizer
    from tokenvault.vault import TokenVault

    with open(args.config, "rb") as fh:
        config_data = tomllib.load(fh)

    field_map: dict[str, str] = config_data.get("fields", {})
    store = EnvKeyStore()
    tokenizer = HMACTokenizer(key_store=store)
    vault = TokenVault(VaultConfig(key_store=store, tokenizer=tokenizer))

    with (
        open(args.input, newline="") as infile,
        open(args.output, "w", newline="") as outfile,
    ):
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames or []
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in reader:
            out: dict[str, str] = {}
            for col, val in row.items():
                ft_str = field_map.get(col, "custom")
                try:
                    ft = FieldType(ft_str)
                except ValueError:
                    ft = FieldType.CUSTOM
                result = vault.tokenize(PIIField(name=col, field_type=ft, value=val))
                out[col] = result.token
            writer.writerow(out)


def cmd_match(args: argparse.Namespace) -> None:
    print("tokenvault match: not yet implemented.", file=sys.stderr)
    sys.exit(1)


def cmd_audit(args: argparse.Namespace) -> None:
    path = Path(args.log)
    if not path.exists():
        print(f"Log file not found: {path}", file=sys.stderr)
        sys.exit(1)
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            print(json.dumps(json.loads(line), indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="tokenvault",
        description="TokenVault PII tokenization CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_tok = sub.add_parser("tokenize", help="Tokenize a CSV of PII records")
    p_tok.add_argument("--config", required=True, help="Path to TOML config")
    p_tok.add_argument("--input", required=True, help="Input CSV path")
    p_tok.add_argument("--output", required=True, help="Output CSV path")
    p_tok.set_defaults(func=cmd_tokenize)

    p_match = sub.add_parser("match", help="Match two tokenized datasets")
    p_match.add_argument("--config", required=True)
    p_match.add_argument("--left", required=True)
    p_match.add_argument("--right", required=True)
    p_match.add_argument("--fields", required=True)
    p_match.set_defaults(func=cmd_match)

    p_audit = sub.add_parser("audit", help="Query an audit JSONL log")
    p_audit.add_argument("--log", required=True, help="Path to JSONL audit log")
    p_audit.set_defaults(func=cmd_audit)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
