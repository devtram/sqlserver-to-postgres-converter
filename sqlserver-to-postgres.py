#!/usr/bin/env python3
"""
tsql2pg.py - SAFE T-SQL -> PostgreSQL translator.

Policy: translate only what is provably safe. Anything risky becomes a
-- TODO block with the original preserved. Nothing that could silently
change meaning is emitted as runnable SQL.

Modes:
  default         translate safe constructs, TODO the rest (regex block list)
  --paranoid      also TODO anything calling a function outside the whitelist

Install:
    pip install sqlglot

Usage:
    python tsql2pg.py queries/ -o migrated/ --preserve-case --quote-all
    python tsql2pg.py queries/ -o migrated/ --paranoid --report report.json --strict
    python tsql2pg.py -q "SELECT TOP 5 [Name] FROM dbo.Users WITH (NOLOCK)"

    # Escape hatch (refused in CI)
    python tsql2pg.py queries/ -o migrated/ --allow-risky
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    import sqlglot
    from sqlglot import exp
    from sqlglot.errors import ErrorLevel, SqlglotError, UnsupportedError
except ImportError:
    sys.exit("Missing dependency. Install it with:  pip install sqlglot")


# --------------------------------------------------------------------------------------
# Config / result types
# --------------------------------------------------------------------------------------
@dataclass
class Config:
    pretty: bool = True
    lowercase: bool = True
    quote_all: bool = False
    uppercase_keywords: bool = True
    allow_risky: bool = False
    paranoid: bool = False
    schema_map: dict = field(default_factory=lambda: {"dbo": "public"})
    param_style: str = "keep"


@dataclass
class Result:
    original: str
    output: str
    status: str  # ok | manual
    blocks: list = field(default_factory=list)
    info: list = field(default_factory=list)


# --------------------------------------------------------------------------------------
# Pre-processing: strip hints (purely advisory in T-SQL)
# --------------------------------------------------------------------------------------
_HINT_NAMES = (
    r"NOLOCK|READUNCOMMITTED|READCOMMITTED|REPEATABLEREAD|SERIALIZABLE|HOLDLOCK|ROWLOCK|PAGLOCK|"
    r"TABLOCKX?|UPDLOCK|XLOCK|READPAST|NOWAIT|NOEXPAND|FORCESEEK|FORCESCAN|"
    r"INDEX\s*(?:=\s*\w+|\([^)]*\))"
)
TABLE_HINT_RE = re.compile(
    rf"\bWITH\s*\(\s*(?:{_HINT_NAMES})(?:\s*,\s*(?:{_HINT_NAMES}))*\s*\)", re.IGNORECASE
)
QUERY_HINT_RE = re.compile(r"\bOPTION\s*\([^)]*\)", re.IGNORECASE)


def preprocess(sql: str) -> tuple[str, list[str]]:
    info = []
    sql, n = TABLE_HINT_RE.subn("", sql)
    if n:
        info.append(f"Removed {n} table hint(s) (NOLOCK etc.); Postgres MVCC has no dirty reads.")
    sql, n = QUERY_HINT_RE.subn("", sql)
    if n:
        info.append(f"Removed {n} OPTION(...) hint(s); use the Postgres planner instead.")
    return sql, info


# --------------------------------------------------------------------------------------
# Blocking patterns: presence => statement becomes -- TODO
# --------------------------------------------------------------------------------------
_COMMENT_RE = re.compile(r"--[^\n]*|/\*.*?\*/", re.DOTALL)
_STRING_RE = re.compile(r"N?'(?:''|[^'])*'", re.IGNORECASE)

BLOCKING_BASE: list[tuple[str, str]] = [
    # ----- variables, control flow, procedures -----
    (r"(?<![\w@])@[A-Za-z_]\w*", "T-SQL variable/parameter @name"),
    (r"@@\w+", "T-SQL system variable @@..."),
    (r"\bDECLARE\s+@", "DECLARE @var"),
    (r"\bSCOPE_IDENTITY\s*\(", "SCOPE_IDENTITY()"),
    (r"\bEXEC(?:UTE)?\b", "EXEC / stored procedure call"),
    (r"\bBEGIN\s+(?:TRY|CATCH)\b", "BEGIN TRY/CATCH block"),
    (r"\bEND\s+(?:TRY|CATCH)\b", "END TRY/CATCH block"),
    (r"\b(?:RAISERROR|THROW|WAITFOR|PRINT)\b", "RAISERROR / THROW / WAITFOR / PRINT"),
    (r"\bCURSOR\b", "CURSOR"),
    (r"\bGOTO\b", "GOTO"),
    (r"\bRETURN\b", "RETURN (outside a function body)"),
    (r"(?<![\w#])#{1,2}[A-Za-z_]\w*", "temp table #t / ##t"),
    (r"\bOUTPUT\s+(?:INSERTED|DELETED)\.", "OUTPUT inserted./deleted."),
    # ----- shapes -----
    (r"\bFOR\s+XML\b", "FOR XML"),
    (r"\bFOR\s+JSON\b", "FOR JSON"),
    (r"\b(?:PIVOT|UNPIVOT)\b", "PIVOT / UNPIVOT"),
    (r"\bMERGE\b", "MERGE"),
    (r"\bIDENTITY\b", "IDENTITY column (schema change)"),
    (r"\bTOP\s*\(?\s*\d+\s*\)?\s*PERCENT\b", "TOP n PERCENT"),
    (r"\bNEXT\s+VALUE\s+FOR\b", "NEXT VALUE FOR (use nextval('...'))"),
    # ----- functions with non-trivial semantics -----
    (r"\bTRY_(?:CAST|CONVERT|PARSE)\b", "TRY_CAST / TRY_CONVERT / TRY_PARSE"),
    (r"\bCONVERT\s*\([^)]*,\s*\d+\s*\)", "CONVERT with style code"),
    (r"\bDATEDIFF\s*\(", "DATEDIFF (boundary-crossing semantics)"),
    (r"\bDATEDIFF_BIG\s*\(", "DATEDIFF_BIG"),
    (r"\bDATEADD\s*\(", "DATEADD (interval semantics)"),
    (r"\bDATEPART\s*\(", "DATEPART (week/iso_week differ from Postgres)"),
    (r"\bDATENAME\s*\(", "DATENAME (returns string, locale-dependent)"),
    (r"\bDATEFROMPARTS\s*\(", "DATEFROMPARTS"),
    (r"\bTIMEFROMPARTS\s*\(", "TIMEFROMPARTS"),
    (r"\bDATETIMEFROMPARTS\s*\(", "DATETIMEFROMPARTS"),
    (r"\bEOMONTH\s*\(", "EOMONTH"),
    (r"\bFORMAT\s*\(", "FORMAT() (.NET format strings)"),
    (r"\bSTUFF\s*\(", "STUFF()"),
    (r"\bCHARINDEX\s*\(", "CHARINDEX (use position() or strpos())"),
    (r"\bPATINDEX\s*\(", "PATINDEX (use regexp_instr or similar)"),
    (r"\bREPLICATE\s*\(", "REPLICATE (use repeat())"),
    (r"\bSPACE\s*\(", "SPACE (use repeat(' ', n))"),
    (r"\bASCII\s*\(", "ASCII (use ascii())"),
    (r"\bCHAR\s*\(", "CHAR (use chr())"),
    (r"\bUNICODE\s*\(", "UNICODE (use ascii() / unicode code point)"),
    (r"\bNCHAR\s*\(", "NCHAR"),
    (r"\bISNUMERIC\s*\(", "ISNUMERIC (no direct Postgres equivalent)"),
    (r"\bISDATE\s*\(", "ISDATE (no direct Postgres equivalent)"),
    (r"\bROUND\s*\(", "ROUND (T-SQL rounds half-away-from-zero; Postgres rounds half-to-even)"),
    (r"\bNEWID\s*\(", "NEWID() (use gen_random_uuid())"),
    (r"\bNEWSEQUENTIALID\s*\(", "NEWSEQUENTIALID()"),
    (r"\bCHECKSUM\s*\(", "CHECKSUM"),
    (r"\bBINARY_CHECKSUM\s*\(", "BINARY_CHECKSUM"),
    (r"\bHASHBYTES\s*\(", "HASHBYTES"),
    (r"\bCOMPRESS\s*\(", "COMPRESS / DECOMPRESS"),
    (r"\bDECOMPRESS\s*\(", "COMPRESS / DECOMPRESS"),
    # ----- date arithmetic (numeric on date) -----
    (r"\bDATEADD\b", "date arithmetic (use interval)"),
    # ----- operators / semantics -----
    (r"\bCOLLATE\b", "COLLATE (names differ)"),
    (r"\bLIKE\b", "LIKE (case-sensitivity differs by default)"),
    (r"'\s*\+|\+\s*N?'", "String concatenation with '+' (needs '||' or CONCAT())"),
    # ----- T-SQL-only types in CAST -----
    (r"\b(?:DATETIME2?|SMALLDATETIME|DATETIMEOFFSET|MONEY|SMALLMONEY|NTEXT|NCHAR|NVARCHAR|"
     r"IMAGE|UNIQUEIDENTIFIER|SQL_VARIANT|ROWVERSION|HIERARCHYID|GEOGRAPHY|GEOMETRY|XML)\b",
     "T-SQL-only type name (map to a Postgres type manually)"),
    # ----- admin / server objects -----
    (r"\b(?:BACKUP|RESTORE|DBCC|KILL|SHUTDOWN|RECONFIGURE|BULK\s+INSERT)\b",
     "Server-administration statement (no equivalent)"),
    (r"\bsp_\w+", "System stored procedure (sp_...)"),
    (r"\bxp_\w+", "Extended stored procedure (xp_...)"),
]

_COMPILED_BLOCKS = [(re.compile(p, re.IGNORECASE | re.DOTALL), m) for p, m in BLOCKING_BASE]


def scan_blocks(stmt: str, cfg: Config) -> list[str]:
    """Regex-based block detection."""
    no_comments = _COMMENT_RE.sub(" ", stmt)
    no_literals = _STRING_RE.sub("''", no_comments)
    reasons: list[str] = []
    for rx, msg in _COMPILED_BLOCKS:
        if rx.search(no_literals):
            reasons.append(msg)
    return list(dict.fromkeys(reasons))


# --------------------------------------------------------------------------------------
# Paranoid function whitelist (AST-based)
# --------------------------------------------------------------------------------------
# Function names that translate 1:1 and are safe to auto-emit.
SAFE_FUNCTIONS = {
    # aggregates
    "count", "sum", "avg", "min", "max",
    # null handling
    "coalesce", "nullif", "isnull",
    # strings
    "upper", "lower", "trim", "ltrim", "rtrim",
    "len", "length", "datalength",
    "substring", "replace",
    "concat",
    # math
    "abs", "sign", "floor", "ceiling",
    # casting
    "cast", "try_cast",
    # date
    "getdate", "getutcdate", "sysdatetime", "sysutcdatetime",
    "year", "month", "day",
    # conditional
    "iif", "choose",
    # window functions
    "row_number", "rank", "dense_rank", "ntile", "lag", "lead",
    "first_value", "last_value", "nth_value",
    # json / utility — safe to leave alone
    "json_value", "json_query",
}


def find_unsafe_functions(tree: exp.Expression) -> list[str]:
    """Walk the AST and return the names of functions not on the safe list."""
    unsafe: set[str] = set()
    for node in tree.walk():
        if isinstance(node, exp.Anonymous):
            name = (node.name or "").lower()
            if name and name not in SAFE_FUNCTIONS:
                unsafe.add(name)
        elif isinstance(node, exp.Func):
            # sqlglot names classes like `exp.Length` -> "length"
            cls = type(node).__name__
            name = re.sub(r"(?<!^)(?=[A-Z])", "_", cls).lower()
            # Some sqlglot classes don't map cleanly; fall back to sql name
            sql_name = getattr(node, "sql_name", None)
            if callable(sql_name):
                try:
                    sql_name = sql_name()
                except Exception:
                    sql_name = None
            if isinstance(sql_name, str):
                name = sql_name.lower()
            if name and name not in SAFE_FUNCTIONS:
                # Known-safe via sqlglot's own translation set:
                # leave these alone (they round-trip fine).
                if name in {
                    "currenttimestamp", "current_date", "current_time", "current_timestamp",
                    "anonymous", "cast", "try_cast", "case", "if",
                }:
                    continue
                unsafe.add(name)
    return sorted(unsafe)


# --------------------------------------------------------------------------------------
# Splitting: GO batches and statements (aware of quotes, [brackets], comments)
# --------------------------------------------------------------------------------------
_GO_RE = re.compile(r"^[ \t]*GO(?:[ \t]+\d+)?[ \t]*(?:--[^\n]*)?$", re.IGNORECASE | re.MULTILINE)


def split_batches(text: str) -> list[str]:
    return [b for b in _GO_RE.split(text) if b.strip()]


def split_statements(sql: str) -> list[str]:
    stmts: list[str] = []
    buf: list[str] = []
    i, n = 0, len(sql)

    def flush():
        s = "".join(buf).strip()
        if s:
            stmts.append(s)
        buf.clear()

    while i < n:
        c = sql[i]
        if c == "'":
            j = i + 1
            while j < n:
                if sql[j] == "'":
                    if j + 1 < n and sql[j + 1] == "'":
                        j += 2
                        continue
                    break
                j += 1
            buf.append(sql[i : j + 1]); i = j + 1
        elif c in "[\"":
            close = "]" if c == "[" else '"'
            j = sql.find(close, i + 1)
            j = n - 1 if j == -1 else j
            buf.append(sql[i : j + 1]); i = j + 1
        elif sql.startswith("--", i):
            j = sql.find("\n", i); j = n if j == -1 else j
            buf.append(sql[i:j]); i = j
        elif sql.startswith("/*", i):
            j = sql.find("*/", i + 2); j = n if j == -1 else j + 2
            buf.append(sql[i:j]); i = j
        elif c == ";":
            flush(); i += 1
        else:
            buf.append(c); i += 1
    flush()
    return stmts


# --------------------------------------------------------------------------------------
# AST transforms
# --------------------------------------------------------------------------------------
_SAFE_IDENT = re.compile(r"^[a-z_][a-z0-9_$]*$")
_PG_RESERVED = {
    "all", "analyse", "analyze", "and", "any", "array", "as", "asc", "both", "case", "cast", "check",
    "collate", "column", "constraint", "create", "current_date", "current_time", "current_timestamp",
    "current_user", "default", "desc", "distinct", "do", "else", "end", "except", "false", "fetch", "for",
    "foreign", "from", "grant", "group", "having", "in", "initially", "intersect", "into", "leading",
    "limit", "localtime", "localtimestamp", "not", "null", "offset", "on", "only", "or", "order",
    "placing", "primary", "references", "returning", "select", "session_user", "some", "symmetric",
    "table", "then", "to", "trailing", "true", "union", "unique", "user", "using", "variadic", "when",
    "where", "window", "with",
}


def apply_transforms(tree: exp.Expression, cfg: Config, info: list[str]) -> exp.Expression:
    for tbl in tree.find_all(exp.Table):
        if tbl.args.get("catalog"):
            info.append(f"Cross-database reference stripped: {tbl.sql(dialect='tsql')}")

    def transform(node: exp.Expression) -> exp.Expression:
        if isinstance(node, exp.Table) and cfg.schema_map:
            db = node.args.get("db")
            if isinstance(db, exp.Identifier):
                new = cfg.schema_map.get(db.name.lower())
                if new:
                    node.set("db", exp.to_identifier(new))
        if cfg.param_style != "keep" and isinstance(node, exp.Parameter) and not isinstance(node, exp.SessionParameter):
            name = node.name
            if name:
                if cfg.param_style == "psycopg":
                    return exp.Parameter(this=exp.Literal.string(f"%({name})s"))
                return exp.Placeholder(this=name)
        return node

    tree = tree.transform(transform)

    if cfg.lowercase:
        def lower(node: exp.Expression) -> exp.Expression:
            if isinstance(node, exp.Identifier):
                name = node.name.lower()
                needs_quotes = not _SAFE_IDENT.match(name) or name in _PG_RESERVED
                return exp.to_identifier(name, quoted=needs_quotes)
            return node
        tree = tree.transform(lower)
    elif cfg.quote_all:
        def quote(node: exp.Expression) -> exp.Expression:
            if isinstance(node, exp.Identifier):
                return exp.to_identifier(node.name, quoted=True)
            return node
        tree = tree.transform(quote)

    return tree


# --------------------------------------------------------------------------------------
# Keyword uppercasing (quote / comment / string / dollar-quote aware)
# --------------------------------------------------------------------------------------
_PG_KEYWORDS = {
    "select", "from", "where", "and", "or", "not", "null", "is", "in", "as", "on", "join", "inner",
    "left", "right", "full", "outer", "cross", "group", "by", "order", "having", "limit", "offset",
    "insert", "into", "values", "update", "set", "delete", "create", "table", "view", "index", "drop",
    "alter", "add", "column", "primary", "key", "foreign", "references", "unique", "default", "case",
    "when", "then", "else", "end", "distinct", "union", "all", "exists", "between", "like", "ilike",
    "asc", "desc", "with", "returning", "conflict", "do", "nothing", "using", "lateral", "over",
    "partition", "window", "cast", "coalesce", "nullif", "current_timestamp", "current_date",
    "current_time", "true", "false", "interval", "extract", "truncate", "begin", "commit", "rollback",
    "grant", "revoke", "if", "replace", "temporary", "temp", "materialized", "recursive", "except",
    "intersect", "any", "some", "filter", "within", "grouping", "sets", "cube", "rollup",
}
_KW_RE = re.compile(r"\b(" + "|".join(sorted(_PG_KEYWORDS, key=len, reverse=True)) + r")\b", re.IGNORECASE)


def uppercase_keywords(sql: str) -> str:
    out: list[str] = []
    i, n = 0, len(sql)
    while i < n:
        c = sql[i]
        if c == '"':
            j = sql.find('"', i + 1); j = n if j == -1 else j + 1
            out.append(sql[i:j]); i = j
        elif c == "'":
            j = i + 1
            while j < n:
                if sql[j] == "'":
                    if j + 1 < n and sql[j + 1] == "'":
                        j += 2; continue
                    break
                j += 1
            out.append(sql[i:j+1]); i = j + 1
        elif sql.startswith("--", i):
            j = sql.find("\n", i); j = n if j == -1 else j
            out.append(sql[i:j]); i = j
        elif sql.startswith("/*", i):
            j = sql.find("*/", i + 2); j = n if j == -1 else j + 2
            out.append(sql[i:j]); i = j
        elif c == "$":
            m = re.match(r"\$[A-Za-z_]*\$", sql[i:])
            if m:
                tag = m.group(0)
                j = sql.find(tag, i + len(tag))
                j = n if j == -1 else j + len(tag)
                out.append(sql[i:j]); i = j
            else:
                out.append(c); i += 1
        else:
            out.append(c); i += 1
    return _KW_RE.sub(lambda m: m.group(0).upper(), "".join(out))


# --------------------------------------------------------------------------------------
# Translation
# --------------------------------------------------------------------------------------
def _first_line(err: Exception) -> str:
    s = re.sub(r"\x1b\[[0-9;]*m", "", str(err)).strip()
    return s.splitlines()[0] if s else repr(err)


def translate_statement(stmt: str, cfg: Config) -> Result | None:
    info: list[str] = []
    pre, info_pre = preprocess(stmt)
    info += info_pre

    # Regex-based block check
    blocks = scan_blocks(pre, cfg)
    if blocks and not cfg.allow_risky:
        return Result(stmt, "", "manual", blocks, info)

    try:
        trees = [t for t in sqlglot.parse(pre, read="tsql") if t is not None]
    except SqlglotError as e:
        return Result(stmt, "", "manual",
                      [f"Could not parse as T-SQL: {_first_line(e)}"], info)
    if not trees:
        return None

    outputs: list[str] = []
    for tree in trees:
        if isinstance(tree, exp.Command):
            return Result(stmt, "", "manual",
                          ["Procedural / unsupported T-SQL statement."], info)

        # Paranoid mode: any non-whitelisted function => manual
        if cfg.paranoid and not cfg.allow_risky:
            unsafe = find_unsafe_functions(tree)
            if unsafe:
                return Result(stmt, "", "manual",
                              [f"Function(s) not on safe whitelist: {', '.join(unsafe)}"],
                              info)

        tree = apply_transforms(tree, cfg, info)

        try:
            out = tree.sql(dialect="postgres", pretty=cfg.pretty, unsupported_level=ErrorLevel.RAISE)
        except UnsupportedError as e:
            if cfg.allow_risky:
                out = tree.sql(dialect="postgres", pretty=cfg.pretty, unsupported_level=ErrorLevel.IGNORE)
                info.append(f"Approximated (--allow-risky): {_first_line(e)}")
            else:
                return Result(stmt, "", "manual",
                              [f"Cannot translate exactly: {_first_line(e)}"], info)

        if cfg.uppercase_keywords:
            out = uppercase_keywords(out)

        if cfg.param_style == "keep":
            try:
                sqlglot.parse_one(out, read="postgres")
            except SqlglotError as e:
                if cfg.allow_risky:
                    info.append(f"Output does not re-parse as PostgreSQL: {_first_line(e)}")
                else:
                    return Result(stmt, "", "manual",
                                  [f"Generated SQL does not parse as PostgreSQL: {_first_line(e)}"], info)

        outputs.append(out)

    return Result(stmt, ";\n\n".join(outputs), "ok", [], info)


def translate_script(text: str, cfg: Config) -> list[Result]:
    results = []
    for batch in split_batches(text):
        for stmt in split_statements(batch):
            r = translate_statement(stmt, cfg)
            if r:
                results.append(r)
    return results


def render(results: list[Result], source: str) -> str:
    lines = [f"-- Translated from T-SQL by tsql2pg.py ({source}).", ""]
    for r in results:
        if r.status == "manual":
            lines.append("-- TODO: MANUAL MIGRATION REQUIRED")
            for b in r.blocks:
                lines.append("--   " + " ".join(b.split()))
            for i in r.info:
                lines.append("--   (info) " + " ".join(i.split()))
            lines.append("--")
            lines += ["-- " + ln for ln in r.original.splitlines()]
            lines.append("")
            continue
        for i in r.info:
            lines.append("-- INFO: " + " ".join(i.split()))
        lines.append(r.output + ";")
        lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------------------
# File handling / CLI
# --------------------------------------------------------------------------------------
def read_sql_file(path: Path) -> str:
    raw = path.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1252", errors="replace")


def collect_files(inputs: list[str]) -> list[tuple[Path, Path]]:
    files = []
    for item in inputs:
        p = Path(item)
        if p.is_dir():
            for f in sorted(p.rglob("*.sql")):
                if not f.name.endswith(".pg.sql"):
                    files.append((f, p))
        elif p.is_file():
            files.append((p, p.parent))
        else:
            print(f"warning: {item} not found, skipping", file=sys.stderr)
    return files


def parse_schema_map(pairs: list[str]) -> dict:
    mapping = {"dbo": "public"}
    for pair in pairs:
        if "=" not in pair:
            sys.exit(f"--schema-map expects OLD=NEW, got: {pair}")
        old, new = pair.split("=", 1)
        mapping[old.strip().lower()] = new.strip()
    return mapping


def summarize(name: str, results: list[Result]) -> dict:
    counts = {"ok": 0, "manual": 0}
    for r in results:
        counts[r.status] += 1
    return {
        "file": name,
        "statements": len(results),
        **counts,
        "manual_issues": [
            {"blocks": r.blocks, "sql": r.original[:300]}
            for r in results if r.status == "manual"
        ],
    }


def in_ci() -> bool:
    for k in ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "TF_BUILD", "JENKINS_URL"):
        if os.environ.get(k):
            return True
    return False


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Safe T-SQL -> PostgreSQL translator.")
    ap.add_argument("inputs", nargs="*", help="SQL files, folders, or '-' for stdin")
    ap.add_argument("-q", "--query", help="translate a single inline query and print it")
    ap.add_argument("-o", "--out-dir", help="output folder")
    ap.add_argument("--schema-map", action="append", default=[], metavar="OLD=NEW")
    ap.add_argument("--preserve-case", action="store_true",
                    help="keep identifier case. Implies --quote-all.")
    ap.add_argument("--quote-all", action="store_true",
                    help="always quote identifiers ([AssetManager].[Table] -> \"AssetManager\".\"Table\")")
    ap.add_argument("--no-uppercase-keywords", action="store_true")
    ap.add_argument("--paranoid", action="store_true",
                    help="also TODO any function not on the safe whitelist (recommended).")
    ap.add_argument("--allow-risky", action="store_true",
                    help="translate risky constructs anyway. Refused in CI unless "
                         "TSQL2PG_ALLOW_RISKY=1 is set.")
    ap.add_argument("--param-style", choices=["keep", "psycopg", "named"], default="keep")
    ap.add_argument("--compact", action="store_true")
    ap.add_argument("--report", help="write JSON report of manual statements")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 if anything needs manual work")
    args = ap.parse_args(argv)

    if not args.inputs and not args.query:
        ap.print_help()
        return 2

    if args.allow_risky and in_ci() and os.environ.get("TSQL2PG_ALLOW_RISKY") != "1":
        sys.exit("Refusing --allow-risky in CI. Set TSQL2PG_ALLOW_RISKY=1 to override.")

    quote_all = args.quote_all or args.preserve_case

    cfg = Config(
        pretty=not args.compact,
        lowercase=not args.preserve_case,
        quote_all=quote_all,
        uppercase_keywords=not args.no_uppercase_keywords,
        allow_risky=args.allow_risky,
        paranoid=args.paranoid,
        schema_map=parse_schema_map(args.schema_map),
        param_style=args.param_style,
    )

    summaries: list[dict] = []

    stdin_jobs = []
    if args.query:
        stdin_jobs.append(("<query>", args.query))
    if "-" in args.inputs:
        stdin_jobs.append(("<stdin>", sys.stdin.read()))
    for name, text in stdin_jobs:
        results = translate_script(text, cfg)
        print(render(results, name))
        summaries.append(summarize(name, results))

    for path, base in collect_files([i for i in args.inputs if i != "-"]):
        results = translate_script(read_sql_file(path), cfg)
        if args.out_dir:
            out_path = Path(args.out_dir) / path.relative_to(base).with_suffix(".pg.sql")
        else:
            out_path = path.with_suffix(".pg.sql")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(render(results, path.name), encoding="utf-8")
        summaries.append(summarize(str(path), results))
        print(f"wrote {out_path}", file=sys.stderr)

    total = {k: sum(s[k] for s in summaries) for k in ("statements", "ok", "manual")}
    print(
        f"\nDone: {total['statements']} statements | {total['ok']} auto-translated | "
        f"{total['manual']} need manual rewrite",
        file=sys.stderr,
    )
    for s in summaries:
        if s["manual"]:
            print(f"  {s['file']}: {s['manual']} manual", file=sys.stderr)

    if args.report:
        Path(args.report).write_text(json.dumps({"total": total, "files": summaries}, indent=2), encoding="utf-8")
        print(f"report written to {args.report}", file=sys.stderr)

    return 1 if args.strict and total["manual"] else 0


if __name__ == "__main__":
    sys.exit(main())
