"""Stage 1 Rule Matcher."""

import fnmatch
from typing import Any

from pydantic import BaseModel, Field

from engine3.contracts.models import InternalGraph, Rule


class MatchEvidence(BaseModel):
    rule_id: str
    principal_id: str
    permission_id: str | None = None
    target_id: str
    edge_id: str | None = None
    flags: list[str] = Field(default_factory=list)
    deny_present: bool = False
    condition_unevaluated: bool = False
    reason: str = ""


class RuleMatchResult(BaseModel):
    rule_id: str
    status: str  # MATCHED, NO_MATCH, NOT_REPRESENTABLE, SKIPPED_INACTIVE, UNSUPPORTED_CONSTRUCT
    matches: list[MatchEvidence] = Field(default_factory=list)
    reason: str = ""
    rulebook_origin: str = "synthetic"


class Stage1Matcher:
    """Stage 1 Rule Matching Engine."""

    @staticmethod
    def _action_matches(pattern: str, action: str) -> bool:
        return fnmatch.fnmatch(action.lower(), pattern.lower())

    @staticmethod
    def _resource_matches(pattern: str, resource_arn: str) -> bool:
        if pattern == "*":
            return True
        return fnmatch.fnmatch(resource_arn.lower(), pattern.lower())

    def match_rules(self, graph: InternalGraph, rules: list[Rule], rulebook_origin: str = "active") -> list[RuleMatchResult]:
        results: list[RuleMatchResult] = []

        # Map principals by ID & type
        principals_by_type: dict[str, list[Any]] = {}
        for p in graph.principals:
            p_type_lower = p.type.lower()
            principals_by_type.setdefault(p_type_lower, []).append(p)

        # Map edges: principal -> permission node
        principal_perm_edges: dict[str, list[Any]] = {}
        # Map edges: permission node -> target resource/role
        perm_target_edges: dict[str, list[Any]] = {}

        for edge in graph.edges:
            if edge.type == "HAS_PERMISSION":
                principal_perm_edges.setdefault(edge.source, []).append(edge)
            elif edge.type == "APPLIES_TO":
                perm_target_edges.setdefault(edge.source, []).append(edge)

        # Map permission nodes
        permissions_by_id = {p.id: p for p in graph.permissions}
        resources_by_id = {r.id: r for r in graph.resources}
        roles_by_id = {p.id: p for p in graph.principals if p.type == "Role"}
        users_by_id = {p.id: p for p in graph.principals if p.type == "User"}

        # Collect Deny statements across graph to check overlaps
        deny_permissions = [p for p in graph.permissions if p.effect == "Deny"]

        for rule in rules:
            if rule.status != "ACTIVE":
                results.append(
                    RuleMatchResult(
                        rule_id=rule.rule_id,
                        status="SKIPPED_INACTIVE",
                        reason=f"Rule status is '{rule.status}'",
                        rulebook_origin=rulebook_origin,
                    )
                )
                continue

            if rule.relationship == "not_representable":
                results.append(
                    RuleMatchResult(
                        rule_id=rule.rule_id,
                        status="NOT_REPRESENTABLE",
                        reason="Relationship or resource type is not representable in IAMGraph v0.1",
                        rulebook_origin=rulebook_origin,
                    )
                )
                continue

            rule_p_type = rule.principal_type.lower()
            matching_principals = principals_by_type.get(rule_p_type, [])

            matches: list[MatchEvidence] = []

            for principal in matching_principals:
                has_perm_edges = principal_perm_edges.get(principal.id, [])
                for hp_edge in has_perm_edges:
                    perm_node = permissions_by_id.get(hp_edge.target)
                    if not perm_node or perm_node.effect != "Allow":
                        continue

                    # Unsupported construct check
                    if perm_node.not_actions or perm_node.not_resources:
                        results.append(
                            RuleMatchResult(
                                rule_id=rule.rule_id,
                                status="UNSUPPORTED_CONSTRUCT",
                                reason=f"Permission statement {perm_node.id} uses NotAction/NotResource",
                                rulebook_origin=rulebook_origin,
                            )
                        )
                        break

                    # Check action match
                    actions = perm_node.actions or []
                    action_matched = any(self._action_matches(act, rule.action) for act in actions)
                    if not action_matched:
                        continue

                    # Check targets via APPLIES_TO edges
                    app_edges = perm_target_edges.get(perm_node.id, [])
                    for app_edge in app_edges:
                        target_id = app_edge.target
                        target_arn = ""
                        target_matched = False

                        if target_id in resources_by_id:
                            res = resources_by_id[target_id]
                            target_arn = res.arn
                            if rule.resource_type in (res.resource_type, "secretsmanager_secret", "s3_bucket") or res.resource_type in (rule.resource_type, "secretsmanager_secret", "s3_bucket"):
                                target_matched = True
                        elif target_id in roles_by_id:
                            r_target = roles_by_id[target_id]
                            target_arn = r_target.arn or r_target.id
                            if rule.resource_type in ("iam_role", "role"):
                                target_matched = True
                        elif target_id in users_by_id:
                            u_target = users_by_id[target_id]
                            target_arn = u_target.arn or u_target.id
                            if rule.resource_type in ("iam_user", "user"):
                                target_matched = True

                        if not target_matched:
                            continue

                        # Check resource ARN match against perm_node resources
                        res_patterns = perm_node.resources or []
                        if not any(self._resource_matches(pat, target_arn) for pat in res_patterns):
                            continue

                        # Build match flags
                        flags: list[str] = []
                        cond_unevaluated = False
                        if perm_node.condition or hp_edge.has_condition or app_edge.has_condition:
                            flags.append("condition_unevaluated")
                            cond_unevaluated = True

                        # Extract any custom flags from extras
                        for extra_obj in (perm_node.extras, hp_edge.extras, app_edge.extras):
                            extra_flags = extra_obj.get("flags", [])
                            for f in extra_flags:
                                if f not in flags:
                                    flags.append(f)

                        # Check overlapping Deny statements
                        deny_present = False
                        for deny_p in deny_permissions:
                            deny_actions = deny_p.actions or []
                            if any(self._action_matches(d_act, rule.action) for d_act in deny_actions):
                                flags.append("deny_present")
                                deny_present = True
                                break

                        matches.append(
                            MatchEvidence(
                                rule_id=rule.rule_id,
                                principal_id=principal.id,
                                permission_id=perm_node.id,
                                target_id=target_id,
                                edge_id=app_edge.id,
                                flags=flags,
                                deny_present=deny_present,
                                condition_unevaluated=cond_unevaluated,
                                reason=f"Matched action '{rule.action}' on target '{target_id}'",
                            )
                        )

            # Sort matches deterministically
            matches.sort(key=lambda m: (m.rule_id, m.principal_id, m.target_id, m.edge_id or ""))

            if matches:
                results.append(
                    RuleMatchResult(
                        rule_id=rule.rule_id,
                        status="MATCHED",
                        matches=matches,
                        rulebook_origin=rulebook_origin,
                    )
                )
            else:
                results.append(
                    RuleMatchResult(
                        rule_id=rule.rule_id,
                        status="NO_MATCH",
                        reason="No statements satisfied the rule conditions",
                        rulebook_origin=rulebook_origin,
                    )
                )

        # Sort results deterministically by rule_id
        results.sort(key=lambda r: r.rule_id)
        return results
