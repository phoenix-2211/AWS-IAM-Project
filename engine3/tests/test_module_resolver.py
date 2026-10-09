"""Tests for Pathrunner dynamic module resolution and disk inventory validation."""

import json
from pathlib import Path
import pytest

from engine3.sandbox.module_resolver import PathrunnerModuleResolver


def test_module_resolver_inventory_counts_sum_to_179():
    resolver = PathrunnerModuleResolver()
    stats = resolver.get_stats()

    assert stats.total_rules == 179
    assert stats.resolved_to_disk + stats.id_missing_on_disk + stats.no_id_present == 179
    assert stats.resolved_to_disk == 175
    assert stats.id_missing_on_disk == 4
    assert stats.no_id_present == 0


def test_module_resolver_primary_rule_id_lookup():
    resolver = PathrunnerModuleResolver()

    # Direct primary index lookups
    assert resolver.resolve_by_rule_id("RULE-IAM-001") == "iam-014"
    assert resolver.resolve_by_rule_id("RULE-IAM-003") == "iam-001"
    assert resolver.resolve_by_rule_id("RULE-IAM-005") == "iam-009"
    assert resolver.resolve_by_rule_id("RULE-IAM-S3-001") == "s3-001"
    assert resolver.resolve_by_rule_id("NONEXISTENT_RULE") is None


def test_module_resolver_action_conflicts_surfaced():
    resolver = PathrunnerModuleResolver()
    stats = resolver.get_stats()

    # Actions like iam:passrole and iam:attachrolepolicy map to multiple modules depending on rule context
    assert "iam:passrole" in stats.action_conflicts
    assert len(stats.action_conflicts["iam:passrole"]) > 10
    assert "iam:attachrolepolicy" in stats.action_conflicts


def test_all_active_rules_have_resolvable_id_or_goal_exfiltration():
    """Verify that every active rule in active_rulebook.json has a valid source_path_id."""
    resolver = PathrunnerModuleResolver()
    stats = resolver.get_stats()

    assert len(stats.no_id_list) == 0, f"Found rules lacking source_path_id: {stats.no_id_list}"

    # The only 4 rules missing from the privesc pathfinding inventory are the synthetic target exfiltration goals
    allowed_goal_rules = {
        "RULE-IAM-S3-001",
        "RULE-IAM-S3-002",
        "RULE-IAM-SEC-001",
        "RULE-IAM-SEC-002",
    }
    missing_rule_ids = {item[0] for item in stats.missing_on_disk_list}
    assert missing_rule_ids == allowed_goal_rules
