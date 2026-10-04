"""Internal Engine 3 data models."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SnapshotMetadata(BaseModel):
    snapshot_id: str
    account_id: str
    collected_at: str
    origin: str
    collection_status: str
    collected_resource_types: List[str] = Field(default_factory=list)
    coverage: List[Dict[str, Any]] = Field(default_factory=list)
    extras: Dict[str, Any] = Field(default_factory=dict)


class Principal(BaseModel):
    id: str
    type: str  # User, Role, ServicePrincipal
    arn: Optional[str] = None
    name: Optional[str] = None
    permissions_boundary: Optional[str] = None
    trust_policy: Optional[Dict[str, Any]] = None
    extras: Dict[str, Any] = Field(default_factory=dict)


class PermissionStatement(BaseModel):
    id: str
    type: str = "Permission"
    effect: str  # Allow or Deny
    actions: Optional[List[str]] = None
    not_actions: Optional[List[str]] = None
    resources: Optional[List[str]] = None
    not_resources: Optional[List[str]] = None
    condition: Optional[Dict[str, Any]] = None
    raw_statement: Dict[str, Any] = Field(default_factory=dict)
    provenance: Dict[str, Any] = Field(default_factory=dict)
    extras: Dict[str, Any] = Field(default_factory=dict)


class TargetResource(BaseModel):
    id: str
    type: str = "Resource"
    resource_type: str
    arn: str
    name: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    extras: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    id: str
    type: str  # HAS_PERMISSION, TRUSTED_BY, APPLIES_TO
    source: str
    target: str
    via_group: Optional[str] = None
    via: Optional[str] = None
    has_condition: Optional[bool] = None
    statement_index: Optional[int] = None
    matched_principal: Optional[str] = None
    extras: Dict[str, Any] = Field(default_factory=dict)


class InternalGraph(BaseModel):
    snapshot: SnapshotMetadata
    principals: List[Principal] = Field(default_factory=list)
    permissions: List[PermissionStatement] = Field(default_factory=list)
    resources: List[TargetResource] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    warnings: List[Dict[str, Any]] = Field(default_factory=list)
    degraded: bool = False
    degraded_reasons: List[str] = Field(default_factory=list)


class Rule(BaseModel):
    rule_id: str
    title: str
    description: str
    condition: Optional[Dict[str, Any]] = None
    principal_type: str
    action: str
    resource_type: str
    relationship: str
    severity: str
    source: Dict[str, Any] = Field(default_factory=dict)
    evidence: str
    mitre: Optional[Dict[str, Any]] = None
    version: str
    status: str
    extras: Dict[str, Any] = Field(default_factory=dict)
