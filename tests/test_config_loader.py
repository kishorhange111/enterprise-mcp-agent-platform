"""Unit tests for customer config-as-code YAML loader and multi-tenant profiles."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.core.config import (
    hydrate_platform_tenants,
    load_customer_config,
    load_tenant_directory,
)
from src.core.models import Principal, Role
from src.core.tenant import TenantRegistry
from src.security.rbac import Permission, RBACEngine

TENANTS_DIR = Path(__file__).resolve().parent.parent / "configs" / "tenants"


def test_load_tenant_directory_and_hydrate_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACME_REGION", "us-west-2")
    configs = load_tenant_directory(TENANTS_DIR)
    assert set(configs.keys()) == {"acme-enterprise", "finserv-eu"}
    assert configs["acme-enterprise"].tenant.data_residency == "us-west-2"
    assert configs["finserv-eu"].guardrails.injection_block_threshold == 0.60

    tenant_registry = TenantRegistry()
    rbac = RBACEngine()
    hydrate_platform_tenants(configs, tenant_registry, rbac)

    assert tenant_registry.is_connector_allowed("acme-enterprise", "ticketing")
    assert not tenant_registry.is_connector_allowed("finserv-eu", "ticketing")

    eu_viewer = Principal(user_id="v1", tenant_id="finserv-eu", roles=(Role.VIEWER,))
    assert rbac.check(eu_viewer, Permission.DOC_READ).allowed
    assert not rbac.check(eu_viewer, Permission.TICKET_READ).allowed


def test_load_customer_config_rejects_invalid_yaml(tmp_path: Path) -> None:
    bad_file = tmp_path / "bad.yaml"
    bad_file.write_text("- not-a-mapping\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_customer_config(bad_file)
