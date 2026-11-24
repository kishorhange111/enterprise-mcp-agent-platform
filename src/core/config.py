"""Customer config-as-code YAML loader for FDE multi-tenant deployments."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from src.core.models import Role, TenantProfile
from src.core.tenant import TenantRegistry
from src.security.rbac import Permission, RBACEngine

_ENV_VAR_RE = re.compile(r"\$\{([A-Z0-9_]+)(?::-(.*?))?\}")


class GuardrailConfig(BaseModel):
    """Per-customer security guardrail settings."""

    injection_block_threshold: float = Field(default=0.70, ge=0.0, le=1.0)
    redact_inputs: bool = True
    redact_outputs: bool = True


class HITLConfig(BaseModel):
    """Per-customer human-in-the-loop approval policy."""

    enforce_four_eyes: bool = True
    default_sla_seconds: int = Field(default=900, ge=30, le=86_400)
    escalation_target: str = "oncall-sre"


class CustomerDeploymentConfig(BaseModel):
    """Declarative FDE customer deployment profile loaded from YAML."""

    tenant: TenantProfile
    guardrails: GuardrailConfig = Field(default_factory=GuardrailConfig)
    hitl: HITLConfig = Field(default_factory=HITLConfig)
    allowed_sql_tables: list[str] = Field(default_factory=lambda: ["orders", "shipments"])
    role_overrides: dict[Role, list[Permission]] = Field(default_factory=dict)


def _interpolate_env(obj: Any) -> Any:
    """Recursively expand `${VAR:-default}` placeholders in parsed YAML values."""
    if isinstance(obj, str):
        def _replace(match: re.Match[str]) -> str:
            var_name = match.group(1)
            default_val = match.group(2) if match.group(2) is not None else ""
            return os.environ.get(var_name, default_val)

        return _ENV_VAR_RE.sub(_replace, obj)
    if isinstance(obj, list):
        return [_interpolate_env(item) for item in obj]
    if isinstance(obj, dict):
        return {k: _interpolate_env(v) for k, v in obj.items()}
    return obj


def load_customer_config(path: str | Path) -> CustomerDeploymentConfig:
    """Load and validate a single customer YAML profile."""
    file_path = Path(path)
    raw_text = file_path.read_text(encoding="utf-8")
    parsed = yaml.safe_load(raw_text)
    if not isinstance(parsed, dict):
        raise ValueError(f"Customer config '{file_path}' must be a YAML mapping")
    expanded = _interpolate_env(parsed)
    return CustomerDeploymentConfig.model_validate(expanded)


def load_tenant_directory(directory: str | Path) -> dict[str, CustomerDeploymentConfig]:
    """Load all *.yaml / *.yml customer profiles from a directory."""
    dir_path = Path(directory)
    configs: dict[str, CustomerDeploymentConfig] = {}
    for file_path in sorted(list(dir_path.glob("*.yaml")) + list(dir_path.glob("*.yml"))):
        cfg = load_customer_config(file_path)
        if cfg.tenant.tenant_id in configs:
            raise ValueError(f"Duplicate tenant_id '{cfg.tenant.tenant_id}' in {file_path}")
        configs[cfg.tenant.tenant_id] = cfg
    return configs


def hydrate_platform_tenants(
    configs: dict[str, CustomerDeploymentConfig],
    tenant_registry: TenantRegistry,
    rbac: RBACEngine | None = None,
) -> None:
    """Register loaded customer configs into TenantRegistry and optional RBACEngine."""
    for cfg in configs.values():
        tenant_registry.register(cfg.tenant)
        if rbac is not None:
            for role, perms in cfg.role_overrides.items():
                rbac.set_tenant_override(cfg.tenant.tenant_id, role, perms)
