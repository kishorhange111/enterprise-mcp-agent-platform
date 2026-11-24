"""Unit tests for the read-only SQL/Postgres MCP connector with AST validation."""

from __future__ import annotations

import sqlite3

import pytest

from src.core import Principal, Role, tenant_scope
from src.mcp import MCPServer, ToolRegistry
from src.mcp.connectors.sql import SQLReadOnlyConnector, SQLSafetyError


def _seed_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute(
        """
        CREATE TABLE orders (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            region TEXT NOT NULL,
            classification TEXT NOT NULL,
            amount REAL NOT NULL,
            customer_email TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE secrets (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            api_secret TEXT NOT NULL
        )
        """
    )
    conn.executemany(
        "INSERT INTO orders VALUES (?, ?, ?, ?, ?, ?)",
        [
            ("ORD-1", "acme", "us-east-1", "internal", 1200.0, "buyer@acme.com"),
            ("ORD-2", "acme", "us-east-1", "internal", 3400.0, "cfo@acme.com"),
            ("ORD-3", "acme", "us-east-1", "confidential", 9900.0, "vip@acme.com"),
            ("ORD-4", "globex", "us-east-1", "internal", 5000.0, "ops@globex.com"),
        ],
    )
    conn.execute("INSERT INTO secrets VALUES ('S1', 'acme', 'super-secret')")
    conn.commit()
    return conn


def test_sql_connector_enforces_tenant_and_classification_rls() -> None:
    conn = _seed_db()
    connector = SQLReadOnlyConnector(conn, allowed_tables={"orders"}, max_rows=10)
    analyst = Principal(user_id="a1", tenant_id="acme", roles=(Role.ANALYST,), region="us-east-1")

    with tenant_scope(analyst) as ctx:
        res = connector.query("SELECT * FROM orders ORDER BY id", ctx)

    # Analyst should ONLY see acme + internal rows (ORD-1, ORD-2), never confidential or globex
    assert res["row_count"] == 2
    assert [r["id"] for r in res["rows"]] == ["ORD-1", "ORD-2"]


def test_sql_connector_supports_cte_and_truncation() -> None:
    conn = _seed_db()
    connector = SQLReadOnlyConnector(conn, allowed_tables={"orders"}, max_rows=1)
    analyst = Principal(user_id="a1", tenant_id="acme", roles=(Role.ANALYST,), region="us-east-1")

    with tenant_scope(analyst) as ctx:
        res = connector.query(
            "WITH high_val AS (SELECT * FROM orders WHERE amount >= 1000) "
            "SELECT * FROM high_val ORDER BY id",
            ctx,
        )
    assert res["row_count"] == 1
    assert res["truncated"] is True


@pytest.mark.parametrize(
    "bad_sql",
    [
        "DROP TABLE orders",
        "DELETE FROM orders WHERE id = 'ORD-1'",
        "UPDATE orders SET amount = 0",
        "SELECT * FROM orders; DROP TABLE orders",
        "SELECT * FROM orders -- bypass check",
        "SELECT * FROM secrets",
        "PRAGMA table_info(orders)",
    ],
)
def test_sql_validator_blocks_unsafe_queries(bad_sql: str) -> None:
    conn = _seed_db()
    connector = SQLReadOnlyConnector(conn, allowed_tables={"orders"})
    analyst = Principal(user_id="a1", tenant_id="acme", roles=(Role.ANALYST,))

    with tenant_scope(analyst) as ctx:
        with pytest.raises(SQLSafetyError):
            connector.query(bad_sql, ctx)


def test_sql_connector_registered_on_mcp_server_redacts_pii() -> None:
    conn = _seed_db()
    registry = ToolRegistry()
    connector = SQLReadOnlyConnector(conn, allowed_tables={"orders"})
    connector.register_tools(registry)
    server = MCPServer(registry=registry)

    analyst = Principal(user_id="a1", tenant_id="acme", roles=(Role.ANALYST,))
    resp = server.handle_rpc(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "sql.query", "arguments": {"sql": "SELECT * FROM orders"}},
        },
        analyst,
    )
    assert resp["result"]["isError"] is False
    assert resp["result"]["meta"]["redacted"] is True
    assert resp["result"]["content"]["rows"][0]["customer_email"] == "[REDACTED_EMAIL]"
