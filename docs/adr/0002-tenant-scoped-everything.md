# ADR 0002: Tenant context is explicit and mandatory

- Status: accepted

## Context
Multi-tenant leaks come from implicit globals. Customer deployments differ in roles, tools and data scopes.

## Decision
A `TenantContext` is passed to every connector call and audit write; per-customer behaviour is config-as-code (`configs/tenants/*.yaml`) validated at load time.

## Consequences
Onboarding a customer is a reviewed YAML change rather than a code change; connectors cannot be called without a tenant.
