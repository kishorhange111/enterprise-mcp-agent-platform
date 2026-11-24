"""Enterprise read-only SQL/Postgres MCP connector with AST/token safety validation."""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from typing import Any

from src.core.models import RiskLevel
from src.core.tenant import TenantContext
from src.mcp.registry import ToolRegistry, ToolSpec
from src.security.policies import PolicyEngine
from src.security.rbac import Permission


class SQLSafetyError(ValueError):
    """Raised when a SQL query violates read-only AST/security constraints."""


@dataclass(frozen=True)
class ValidatedQuery:
    """Result of validating and normalizing a read-only SQL query."""

    sql: str
    referenced_tables: tuple[str, ...]
    applied_limit: int


class SQLSafetyValidator:
    """Token/AST-based validator enforcing single-statement read-only SQL."""

    _FORBIDDEN_KEYWORDS: frozenset[str] = frozenset(
        {
            "INSERT",
            "UPDATE",
            "DELETE",
            "DROP",
            "ALTER",
            "TRUNCATE",
            "CREATE",
            "REPLACE",
            "MERGE",
            "GRANT",
            "REVOKE",
            "ATTACH",
            "DETACH",
            "PRAGMA",
            "VACUUM",
            "COPY",
            "EXEC",
            "EXECUTE",
            "CALL",
            "INTO",
            "LOAD_EXTENSION",
            "PG_SLEEP",
        }
    )

    _TOKEN_RE = re.compile(
        r"""
        (?P<comment>--[^\n]*|/\*[\s\S]*?\*/) |
        (?P<string>'(?:''|[^'])*') |
        (?P<quoted_ident>"(?:""|[^"])*") |
        (?P<word>[A-Za-z_][A-Za-z0-9_$]*) |
        (?P<number>\d+(?:\.\d+)?) |
        (?P<semicolon>;) |
        (?P<punct>[(),.*=<>!+\-/]) |
        (?P<ws>\s+)
        """,
        re.VERBOSE,
    )

    def __init__(
        self,
        allowed_tables: set[str] | frozenset[str] | None = None,
        max_rows: int = 500,
    ) -> None:
        self.allowed_tables = (
            frozenset(t.lower() for t in allowed_tables) if allowed_tables is not None else None
        )
        self.max_rows = max_rows

    def validate(self, sql: str, limit: int | None = None) -> ValidatedQuery:
        """Validate SQL tokens, enforce read-only SELECT/CTE, table allowlist, and LIMIT."""
        if not sql or not sql.strip():
            raise SQLSafetyError("SQL query must not be empty")

        tokens: list[tuple[str, str]] = []
        pos = 0
        for match in self._TOKEN_RE.finditer(sql):
            if match.start() != pos:
                raise SQLSafetyError(f"Unexpected SQL syntax near: {sql[pos:match.start()]!r}")
            pos = match.end()
            kind = match.lastgroup or ""
            value = match.group(0)
            if kind == "ws":
                continue
            if kind == "comment":
                raise SQLSafetyError("SQL comments (-- or /* */) are disallowed for safety")
            tokens.append((kind, value))

        if pos != len(sql):
            raise SQLSafetyError(f"Unrecognized trailing SQL syntax: {sql[pos:]!r}")

        if not tokens:
            raise SQLSafetyError("SQL query contains no executable tokens")

        # Reject stacked queries (semicolon followed by any token)
        semicolon_indices = [idx for idx, (kind, _) in enumerate(tokens) if kind == "semicolon"]
        if len(semicolon_indices) > 1 or (
            len(semicolon_indices) == 1 and semicolon_indices[0] != len(tokens) - 1
        ):
            raise SQLSafetyError("Stacked / multi-statement SQL queries are forbidden")

        clean_sql = sql.strip().rstrip(";").strip()
        if semicolon_indices:
            tokens = tokens[:-1]

        first_kind, first_val = tokens[0]
        if first_kind != "word" or first_val.upper() not in {"SELECT", "WITH"}:
            raise SQLSafetyError("Only read-only SELECT (or WITH ... SELECT) queries are permitted")

        words_upper = [val.upper() for kind, val in tokens if kind == "word"]
        if first_val.upper() == "WITH" and "SELECT" not in words_upper:
            raise SQLSafetyError("CTE queries must contain a SELECT statement")

        for word in words_upper:
            if word in self._FORBIDDEN_KEYWORDS:
                raise SQLSafetyError(f"Forbidden SQL keyword detected: {word}")

        # Extract tables referenced after FROM / JOIN (excluding CTE aliases)
        cte_names = self._extract_cte_names(tokens)
        referenced_tables = self._extract_table_names(tokens, cte_names)

        if self.allowed_tables is not None:
            disallowed = [t for t in referenced_tables if t not in self.allowed_tables]
            if disallowed:
                raise SQLSafetyError(f"Access to table(s) not allowed: {disallowed}")

        effective_limit = min(limit or self.max_rows, self.max_rows)
        if effective_limit < 1:
            raise SQLSafetyError("Row limit must be >= 1")

        # Wrap query in outer LIMIT if not already bounded or to guarantee hard cap
        bounded_sql = f"SELECT * FROM ({clean_sql}) AS _mcp_subq LIMIT {effective_limit + 1}"
        return ValidatedQuery(
            sql=bounded_sql,
            referenced_tables=tuple(referenced_tables),
            applied_limit=effective_limit,
        )

    @staticmethod
    def _extract_cte_names(tokens: list[tuple[str, str]]) -> set[str]:
        ctes: set[str] = set()
        for idx, (kind, val) in enumerate(tokens[:-2]):
            if kind == "word" and val.upper() == "WITH":
                nxt_kind, nxt_val = tokens[idx + 1]
                if nxt_kind == "word" and nxt_val.upper() != "RECURSIVE":
                    ctes.add(nxt_val.lower())
            if kind == "word" and idx + 1 < len(tokens):
                nxt_kind, nxt_val = tokens[idx + 1]
                if nxt_kind == "word" and nxt_val.upper() == "AS":
                    ctes.add(val.lower())
        return ctes

    @staticmethod
    def _extract_table_names(
        tokens: list[tuple[str, str]], cte_names: set[str]
    ) -> list[str]:
        tables: list[str] = []
        for idx, (kind, val) in enumerate(tokens[:-1]):
            if kind == "word" and val.upper() in {"FROM", "JOIN"}:
                nxt_kind, nxt_val = tokens[idx + 1]
                if nxt_kind in {"word", "quoted_ident"}:
                    name = nxt_val.strip('"').lower()
                    if name not in cte_names and name not in tables:
                        tables.append(name)
        return tables


class SQLReadOnlyConnector:
    """Read-only SQL/Postgres MCP connector enforcing AST validation & row-level tenancy."""

    CONNECTOR_NAME = "sql_readonly"

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        allowed_tables: set[str] | frozenset[str] | None = None,
        max_rows: int = 500,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        self._conn = connection
        self._conn.row_factory = sqlite3.Row
        self.validator = SQLSafetyValidator(allowed_tables=allowed_tables, max_rows=max_rows)
        self.policy_engine = policy_engine or PolicyEngine()

    def query(
        self,
        sql: str,
        ctx: TenantContext,
        *,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """Validate and execute a read-only SQL query scoped to the active tenant."""
        validated = self.validator.validate(sql, limit=limit)
        cursor = self._conn.execute(validated.sql)
        raw_rows = [dict(row) for row in cursor.fetchall()]

        # Enforce row-level security (tenant_id, region, classification) on every returned row
        scoped_rows = self.policy_engine.filter_rows(
            ctx.principal, raw_rows, resource_type="sql_row"
        )
        truncated = len(scoped_rows) > validated.applied_limit
        final_rows = scoped_rows[: validated.applied_limit]

        return {
            "tenant_id": ctx.tenant_id,
            "tables": list(validated.referenced_tables),
            "row_count": len(final_rows),
            "truncated": truncated,
            "rows": final_rows,
        }

    def list_tables(self, ctx: TenantContext) -> dict[str, Any]:
        """Return schemas for allowed tables."""
        cursor = self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
        all_tables = [row[0] for row in cursor.fetchall()]
        visible = [
            t
            for t in all_tables
            if self.validator.allowed_tables is None
            or t.lower() in self.validator.allowed_tables
        ]
        schemas: dict[str, list[dict[str, str]]] = {}
        for table in visible:
            col_cur = self._conn.execute(f'PRAGMA table_info("{table}")')
            schemas[table] = [
                {"name": str(c[1]), "type": str(c[2])} for c in col_cur.fetchall()
            ]
        return {"tenant_id": ctx.tenant_id, "tables": schemas}

    def register_tools(self, registry: ToolRegistry) -> None:
        """Register SQL connector tools onto an MCP ToolRegistry."""
        registry.register(
            ToolSpec(
                name="sql.query",
                description="Execute a validated read-only SQL SELECT query with tenant RLS.",
                connector=self.CONNECTOR_NAME,
                required_permission=Permission.SQL_READ,
                risk_level=RiskLevel.MEDIUM,
                input_schema={
                    "type": "object",
                    "properties": {
                        "sql": {"type": "string", "minLength": 1},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 5000},
                    },
                    "required": ["sql"],
                    "additionalProperties": False,
                },
                handler=lambda args, ctx: self.query(args["sql"], ctx, limit=args.get("limit")),
                tags=("sql", "readonly", "analytics"),
            )
        )
        registry.register(
            ToolSpec(
                name="sql.list_tables",
                description="Inspect allowed database tables and column schemas.",
                connector=self.CONNECTOR_NAME,
                required_permission=Permission.SQL_READ,
                risk_level=RiskLevel.LOW,
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
                handler=lambda args, ctx: self.list_tables(ctx),
                tags=("sql", "schema"),
            )
        )
