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

    results_by_col: dict[str, object] = {}

    with (
        open(args.input, newline="") as infile,
        open(args.output, "w", newline="") as outfile,
    ):
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames or []
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        first_row = True
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
                if first_row:
                    results_by_col[col] = result
            writer.writerow(out)
            first_row = False

    # Emit manifest sidecar when --manifest flag is set
    if getattr(args, "manifest", False):
        _write_manifest(args.output, field_map, results_by_col)


def _write_manifest(
    output_path: str, field_map: dict[str, str], results: dict[str, object]
) -> None:
    from tokenvault.protocols.tokenizer import TokenResult
    from tokenvault.transfer.manifest import FieldMapping, TransferManifest

    field_mappings = []
    for col, result in results.items():
        if not isinstance(result, TokenResult):
            continue
        field_mappings.append(FieldMapping(
            field_name=col,
            field_type=field_map.get(col, "custom"),
            algorithm=result.algorithm,
            key_version=result.key_version,
        ))

    manifest = TransferManifest(
        source_region="unknown",
        destination_region="unknown",
        policy_id="none",
        consent_reference="",
        field_mappings=field_mappings,
    )
    stem = Path(output_path).stem
    manifest_path = Path(output_path).parent / f"{stem}_manifest.json"
    manifest_path.write_text(json.dumps(manifest.to_dict(), indent=2))
    print(f"Manifest written to {manifest_path}", file=sys.stderr)


def cmd_match(args: argparse.Namespace) -> None:
    from tokenvault.matchers.exact import ExactTokenMatcher
    from tokenvault.matchers.ngram import NgramSimilarityMatcher
    from tokenvault.protocols.matcher import Matcher

    algorithm: str = args.algorithm
    threshold: float = float(args.threshold)

    matcher: Matcher
    if algorithm == "exact":
        matcher = ExactTokenMatcher(threshold=threshold)
    elif algorithm == "ngram":
        matcher = NgramSimilarityMatcher(threshold=threshold)
    elif algorithm in ("jaro-winkler", "levenshtein"):
        try:
            if algorithm == "jaro-winkler":
                from tokenvault.matchers.jaro_winkler import JaroWinklerMatcher
                matcher = JaroWinklerMatcher(threshold=threshold)
            else:
                from tokenvault.matchers.levenshtein import LevenshteinMatcher
                matcher = LevenshteinMatcher(threshold=threshold)
        except ImportError:
            print(
                f"Error: algorithm '{algorithm}' requires tokenvault[fuzzy]. "
                "Install with: pip install 'tokenvault[fuzzy]'",
                file=sys.stderr,
            )
            sys.exit(1)
    else:
        print(
            f"Error: unknown algorithm '{algorithm}'. "
            "Supported: exact, ngram, jaro-winkler, levenshtein",
            file=sys.stderr,
        )
        sys.exit(1)

    with open(args.tokens_a, newline="") as fa:
        rows_a = list(csv.DictReader(fa))
    with open(args.tokens_b, newline="") as fb:
        rows_b = list(csv.DictReader(fb))

    if not rows_a or not rows_b:
        print("Error: one or both input files are empty.", file=sys.stderr)
        sys.exit(1)

    # Determine which columns to match
    cols_a = set(rows_a[0].keys())
    cols_b = set(rows_b[0].keys())
    if args.fields:
        match_cols = [c.strip() for c in args.fields.split(",")]
        missing = set(match_cols) - cols_a | set(match_cols) - cols_b
        if missing:
            print(f"Error: columns not found in both files: {sorted(missing)}", file=sys.stderr)
            sys.exit(1)
    else:
        match_cols = sorted(cols_a & cols_b)

    if not match_cols:
        print("Error: no common columns to match.", file=sys.stderr)
        sys.exit(1)

    out_fieldnames = ["row_a", "row_b", "score", "matched"]
    with open(args.output, "w", newline="") as outfile:
        writer = csv.DictWriter(outfile, fieldnames=out_fieldnames)
        writer.writeheader()
        for i, row_a in enumerate(rows_a):
            for j, row_b in enumerate(rows_b):
                scores = [
                    matcher.match(row_a[col], row_b[col]).score
                    for col in match_cols
                    if col in row_a and col in row_b
                ]
                if not scores:
                    continue
                avg = sum(scores) / len(scores)
                writer.writerow({
                    "row_a": i,
                    "row_b": j,
                    "score": round(avg, 6),
                    "matched": avg >= threshold,
                })


def cmd_audit(args: argparse.Namespace) -> None:
    path = Path(args.log)
    if not path.exists():
        print(f"Log file not found: {path}", file=sys.stderr)
        sys.exit(1)

    filters: dict[str, str] = {}
    if getattr(args, "operation", None):
        filters["operation"] = args.operation
    if getattr(args, "field_type", None):
        filters["field_type"] = args.field_type
    if getattr(args, "outcome", None):
        filters["outcome"] = args.outcome
    since = getattr(args, "since", None)
    until = getattr(args, "until", None)

    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if any(record.get(k) != v for k, v in filters.items()):
                continue
            ts = record.get("timestamp", "")
            if since and ts < since:
                continue
            if until and ts > until:
                continue
            print(json.dumps(record, indent=2))


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
    p_tok.add_argument("--manifest", action="store_true", help="Write a manifest sidecar JSON")
    p_tok.set_defaults(func=cmd_tokenize)

    p_match = sub.add_parser("match", help="Match two tokenized CSV datasets")
    p_match.add_argument("--tokens-a", required=True, dest="tokens_a", help="First tokenized CSV")
    p_match.add_argument("--tokens-b", required=True, dest="tokens_b", help="Second tokenized CSV")
    p_match.add_argument("--algorithm", default="exact",
                         help="Matching algorithm: exact|ngram|jaro-winkler|levenshtein")
    p_match.add_argument("--threshold", type=float, default=0.9, help="Match score threshold")
    p_match.add_argument("--fields", default="",
                         help="Comma-separated columns to match (default: all)")
    p_match.add_argument("--output", required=True, help="Output CSV path for matched pairs")
    p_match.set_defaults(func=cmd_match)

    p_audit = sub.add_parser("audit", help="Query an audit JSONL log")
    p_audit.add_argument("--log", required=True, help="Path to JSONL audit log")
    p_audit.add_argument("--operation", help="Filter by operation (tokenize|match|detokenize)")
    p_audit.add_argument("--field-type", dest="field_type", help="Filter by field type")
    p_audit.add_argument("--outcome", help="Filter by outcome (success|denied)")
    p_audit.add_argument("--since", help="ISO-8601 timestamp lower bound")
    p_audit.add_argument("--until", help="ISO-8601 timestamp upper bound")
    p_audit.set_defaults(func=cmd_audit)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
