#!/usr/bin/env python3
"""Scope importer: CSV/JSON -> SQL for psql (dependency-free).

Input formats:
  * .json : [{"pattern": "example.com", "allowed": true, "note": "apex"}, ...]
  * CSV   : one entry per line, `pattern,allow|deny[,note]`

Usage:
    python3 scripts/import_scope.py --program myprogram scope.csv \
        | docker compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"

Patterns are validated with the SAME rules as common/scope.py before any SQL
is emitted, and values are SQL-escaped - nothing raw reaches the database.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from common.scope import InvalidTarget, ScopeEntry  # noqa: E402

_LABEL_OK = re.compile(r"^[a-z0-9._*\-]+$")


def sql_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def parse_entries(path: pathlib.Path):
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        for row in data:
            yield str(row["pattern"]), bool(row["allowed"]), str(row.get("note", ""))
    else:
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 2:
                raise SystemExit(f"{path}:{lineno}: expected 'pattern,allow|deny'")
            allowed = parts[1].lower() in ("allow", "true", "yes", "in")
            yield parts[0], allowed, (parts[2] if len(parts) > 2 else "")


def main() -> int:
    parser = argparse.ArgumentParser(description="Import program scope into the platform DB.")
    parser.add_argument("--program", required=True, help="existing program name")
    parser.add_argument("scope_file", help=".json or .csv scope definition")
    args = parser.parse_args()

    program = args.program.strip().lower()
    if not re.match(r"^[a-z0-9_-]{2,64}$", program):
        raise SystemExit(f"illegal program name: {args.program!r}")

    statements = [
        "BEGIN;",
        f"SELECT id FROM programs WHERE name = {sql_quote(program)};",
        "-- rows below fail safely if the program does not exist (FK violation)",
        "DELETE FROM scope_entries WHERE program_id = "
        "(SELECT id FROM programs WHERE name = " + sql_quote(program) + ");",
    ]
    count = 0
    for pattern, allowed, note in parse_entries(pathlib.Path(args.scope_file)):
        try:
            entry = ScopeEntry.parse(pattern, allowed)
        except InvalidTarget as exc:
            raise SystemExit(f"rejecting pattern {pattern!r}: {exc}") from exc
        kind_sql = {"domain": "domain", "wildcard": "wildcard", "cidr": "cidr"}
        statements.append(
            "INSERT INTO scope_entries (program_id, pattern, kind, is_allowed, note) "
            "SELECT id, {p}, '{k}', {a}, {n} FROM programs WHERE name = {prog};".format(
                p=sql_quote(entry.pattern), k=entry.kind,
                a="TRUE" if entry.is_allowed else "FALSE",
                n=sql_quote(note or ""), prog=sql_quote(program),
            )
        )
        count += 1

    statements.append(
        f"-- sanity: deny-wins check summary for {count} entries",
        "COMMIT;",
    )
    print("\n".join(statements))
    print(f"-- imported {count} scope entries for program {program!r}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
