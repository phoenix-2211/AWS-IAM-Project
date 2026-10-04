"""Internal Engine 3 data models."""

from typing import Any

from pydantic import BaseModel, Field


class SnapshotMetadata(BaseModel):
    snapshot_id: str
    account_id: str
    collected_at: str
    origin: str
    collection_status: str
    collected_resource_types: list[str] = Field(default_factory=list)
    coverage: list[dict[str, Any]] = Field(default_factory=list)
    extras: dict[str, Any] = Field(default_factory=dict)


class Principal(BaseModel):
    id: str
    type: str  # User, Role, ServicePrincipal
    arn: str | None = None
    name: str | None = None
    permissions_boundary: str | None = None
    trust_policy: dict[str, Any] | None = None
    extras: dict[str, Any] = Field(default_factory=dict)


class PermissionStatement(BaseModel):
    id: str
    type: str = "Permission"
    effect: str  # Allow or Deny
    actions: list[str] | None = None
    not_actions: list[str] | None = None
    resources: list[str] | None = None
    not_resources: list[str] | None = None
    condition: dict[str, Any] | None = None
    raw_statement: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)
    extras: dict[str, Any] = Field(default_factory=dict)


class TargetResource(BaseModel):
    id: str
    type: str = "Resource"
    resource_type: str
    arn: str
    name: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    extras: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    id: str
    type: str  # HAS_PERMISSION, TRUSTED_BY, APPLIES_TO
    source: str
    target: str
    via_group: str | None = None
    via: str | None = None
    has_condition: bool | None = None
    statement_index: int | None = None
    matched_principal: str | None = None
    extras: dict[str, Any] = Field(default_factory=dict)


class InternalGraph(BaseModel):
    snapshot: SnapshotMetadata
    principals: list[Principal] = Field(default_factory=list)
    permissions: list[PermissionStatement] = Field(default_factory=list)
    resources: list[TargetResource] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    warnings: list[dict[str, Any]] = Field(default_factory=list)
    degraded: bool = False
    degraded_reasons: list[str] = Field(default_factory=list)


class Rule(BaseModel):
    rule_id: str
    title: str
    description: str
    condition: dict[str, Any] | None = None
    principal_type: str
    action: str
    resource_type: str
    relationship: str
    severity: str
    source: dict[str, Any] = Field(default_factory=dict)
    evidence: Any = ""
    mitre: dict[str, Any] | None = None
    version: str
    status: str
    extras: dict[str, Any] = Field(default_factory=dict)
