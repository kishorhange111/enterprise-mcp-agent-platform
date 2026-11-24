"""Enterprise document store / knowledge base MCP connector with ACL filtering."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from src.core.models import Principal, RiskLevel, Role
from src.core.tenant import TenantContext
from src.mcp.registry import ToolRegistry, ToolSpec
from src.security.policies import PolicyEngine
from src.security.rbac import Permission

_WORD_RE = re.compile(r"[a-z0-9]+")


def _tokenize(text: str) -> list[str]:
    return _WORD_RE.findall(text.lower())


@dataclass(frozen=True)
class Document:
    """Enterprise knowledge base document with tenant and ACL metadata."""

    doc_id: str
    tenant_id: str
    title: str
    content: str
    classification: str = "internal"
    region: str = "us-east-1"
    allowed_groups: tuple[str, ...] = field(default_factory=tuple)
    tags: tuple[str, ...] = field(default_factory=tuple)
    source_uri: str = ""

    def to_policy_row(self) -> dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "tenant_id": self.tenant_id,
            "region": self.region,
            "classification": self.classification,
        }


class KnowledgeBaseConnector:
    """ACL-enforced enterprise knowledge base connector with lexical BM25-style ranking."""

    CONNECTOR_NAME = "knowledge_base"

    def __init__(self, policy_engine: PolicyEngine | None = None) -> None:
        self._docs: dict[str, Document] = {}
        self.policy_engine = policy_engine or PolicyEngine()

    def ingest(self, doc: Document) -> None:
        """Index or update a document in the knowledge store."""
        self._docs[doc.doc_id] = doc

    def _is_accessible(self, principal: Principal, doc: Document) -> bool:
        if not self.policy_engine.evaluate_row(
            principal, doc.to_policy_row(), resource_type="knowledge_doc"
        ):
            return False
        if doc.allowed_groups and Role.ADMIN not in principal.roles:
            user_groups = set(principal.attributes.get("groups", ()))
            if not user_groups.intersection(doc.allowed_groups):
                return False
        return True

    def search(
        self,
        ctx: TenantContext,
        *,
        query: str,
        top_k: int = 5,
        tag: str | None = None,
    ) -> dict[str, Any]:
        """Search accessible documents for the active tenant using BM25-style scoring."""
        query_terms = _tokenize(query)
        if not query_terms:
            return {"tenant_id": ctx.tenant_id, "query": query, "results": []}

        # Pre-filter by tenant, region, classification, and group ACL BEFORE scoring
        eligible = [
            doc
            for doc in self._docs.values()
            if self._is_accessible(ctx.principal, doc) and (tag is None or tag in doc.tags)
        ]
        if not eligible:
            return {"tenant_id": ctx.tenant_id, "query": query, "results": []}

        # Compute document frequency across the eligible corpus
        doc_tokens: list[tuple[Document, Counter[str], Counter[str]]] = []
        df: Counter[str] = Counter()
        for doc in eligible:
            title_counts = Counter(_tokenize(doc.title))
            body_counts = Counter(_tokenize(doc.content))
            doc_tokens.append((doc, title_counts, body_counts))
            for term in set(title_counts) | set(body_counts):
                df[term] += 1

        n_docs = len(eligible)
        scored: list[tuple[float, Document]] = []
        for doc, title_counts, body_counts in doc_tokens:
            score = 0.0
            for term in query_terms:
                tf = 2.0 * title_counts[term] + 1.0 * body_counts[term]
                if tf > 0:
                    idf = math.log((n_docs + 1.0) / (df[term] + 0.5)) + 1.0
                    score += (tf / (tf + 1.5)) * idf
            if score > 0.0:
                scored.append((round(score, 4), doc))

        scored.sort(key=lambda pair: (-pair[0], pair[1].doc_id))
        results = [
            {
                "doc_id": doc.doc_id,
                "title": doc.title,
                "score": score,
                "classification": doc.classification,
                "source_uri": doc.source_uri,
                "snippet": doc.content[:220],
                "tags": list(doc.tags),
            }
            for score, doc in scored[:top_k]
        ]
        return {"tenant_id": ctx.tenant_id, "query": query, "results": results}

    def get_document(self, ctx: TenantContext, doc_id: str) -> dict[str, Any]:
        """Fetch full document content if accessible to the caller."""
        doc = self._docs.get(doc_id)
        if doc is None or not self._is_accessible(ctx.principal, doc):
            raise PermissionError(f"Document '{doc_id}' is not accessible or does not exist")
        return {
            "doc_id": doc.doc_id,
            "tenant_id": doc.tenant_id,
            "title": doc.title,
            "content": doc.content,
            "classification": doc.classification,
            "source_uri": doc.source_uri,
            "tags": list(doc.tags),
        }

    def register_tools(self, registry: ToolRegistry) -> None:
        """Register knowledge base MCP tools onto a ToolRegistry."""
        registry.register(
            ToolSpec(
                name="docs.search",
                description="Search enterprise knowledge base with strict tenant & ACL filtering.",
                connector=self.CONNECTOR_NAME,
                required_permission=Permission.DOC_READ,
                risk_level=RiskLevel.LOW,
                input_schema={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "minLength": 1},
                        "top_k": {"type": "integer", "minimum": 1, "maximum": 25},
                        "tag": {"type": "string"},
                    },
                    "required": ["query"],
                    "additionalProperties": False,
                },
                handler=lambda args, ctx: self.search(
                    ctx,
                    query=args["query"],
                    top_k=args.get("top_k", 5),
                    tag=args.get("tag"),
                ),
                tags=("docs", "rag", "acl"),
            )
        )
        registry.register(
            ToolSpec(
                name="docs.get",
                description="Retrieve a full knowledge base document by ID (ACL-enforced).",
                connector=self.CONNECTOR_NAME,
                required_permission=Permission.DOC_READ,
                risk_level=RiskLevel.LOW,
                input_schema={
                    "type": "object",
                    "properties": {"doc_id": {"type": "string", "minLength": 1}},
                    "required": ["doc_id"],
                    "additionalProperties": False,
                },
                handler=lambda args, ctx: self.get_document(ctx, args["doc_id"]),
                tags=("docs", "acl"),
            )
        )
