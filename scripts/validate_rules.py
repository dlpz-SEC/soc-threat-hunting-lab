"""Lint the auth Sigma rules for this lab's conventions.

Complements `sigma check` (which validates Sigma syntax/taxonomy) with the
repo-specific rules that mirror dlpz-SEC/detection-as-code:
  * title convention  '[Auth] - <Behavior>'
  * a MITRE technique-level tag (attack.t####) on every rule
  * a mandatory falsepositives field on every detection (non-correlation) rule
  * a custom: block with lifecycle/confidence/false_positive_rate on
    production-or-experimental detection rules

Usage:
  python scripts/validate_rules.py --rules-dir rules/ [--strict]

Exit code 1 if any rule fails (with --strict, warnings are errors too).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

TITLE_RE = re.compile(r"^\[Auth\] - .+")
TECH_TAG_RE = re.compile(r"^attack\.t\d{4}", re.IGNORECASE)


def _docs(path: Path):
    return [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d]


def check_rule(path: Path) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    docs = _docs(path)
    if not docs:
        return [f"{path}: no YAML documents"], warnings

    for doc in docs:
        title = doc.get("title", "")
        is_correlation = "correlation" in doc
        is_detection = "detection" in doc

        if not TITLE_RE.match(title):
            errors.append(f"{path}: title '{title}' must match '[Auth] - <Behavior>'")

        tags = doc.get("tags", []) or []
        if not any(TECH_TAG_RE.match(t) for t in tags):
            errors.append(f"{path}: '{title}' has no technique-level attack.t#### tag")

        if is_detection and not is_correlation:
            if not doc.get("falsepositives"):
                errors.append(f"{path}: '{title}' is missing falsepositives")
            custom = doc.get("custom") or {}
            for field in ("lifecycle", "confidence", "false_positive_rate"):
                if field not in custom:
                    warnings.append(f"{path}: '{title}' custom block missing '{field}'")
            if "id" not in doc:
                errors.append(f"{path}: '{title}' is missing id")

        if is_correlation and "rules" not in doc["correlation"]:
            errors.append(f"{path}: correlation '{title}' references no base rules")

    return errors, warnings


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate auth Sigma rules.")
    parser.add_argument("--rules-dir", default="rules/", help="Directory of .yml rules.")
    parser.add_argument("--strict", action="store_true", help="Treat warnings as errors.")
    args = parser.parse_args()

    rule_files = sorted(Path(args.rules_dir).rglob("*.yml"))
    if not rule_files:
        print(f"No rules found under {args.rules_dir}")
        return 1

    all_errors: list[str] = []
    all_warnings: list[str] = []
    for path in rule_files:
        errors, warnings = check_rule(path)
        all_errors += errors
        all_warnings += warnings

    for w in all_warnings:
        print(f"WARN  {w}")
    for e in all_errors:
        print(f"ERROR {e}")

    failed = bool(all_errors) or (args.strict and bool(all_warnings))
    n = len(rule_files)
    if failed:
        print(f"\nFAILED — {len(all_errors)} error(s), {len(all_warnings)} warning(s) "
              f"across {n} rule file(s).")
        return 1
    print(f"OK — {n} rule file(s) validated, {len(all_warnings)} warning(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
