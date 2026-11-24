"""ASGI HTTP & Server-Sent Events (SSE) service layer for the MCP Agent Platform."""

from src.api.app import PlatformContainer, create_app

__all__ = ["PlatformContainer", "create_app"]
