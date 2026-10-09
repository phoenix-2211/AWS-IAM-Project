"""Module Resolver and Registry for Pathrunner / pathfinding.cloud modules.

Dynamically derives module mappings from active_rulebook.json and validates
module existence against the on-disk YAML inventory in vendor/pathfinding.cloud.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ModuleResolutionStats:
    total_rules: int
    resolved_to_disk: int
    id_missing_on_disk: int
    no_id_present: int
    action_conflicts: dict[str, list[str]]
    resolved_list: list[tuple[str, str, str]]
    missing_on_disk_list: list[tuple[str, str, str, str]]
    no_id_list: list[tuple[str, str, str]]


class PathrunnerModuleResolver:
    """Dynamically builds and validates Pathrunner module lookups from rulebook rules."""

    def __init__(
        self,
        rulebook_path: Path | str | None = None,
        inventory_dir: Path | str | None = None,
    ) -> None:
        if rulebook_path is None:
            candidates = [
                Path("rulebook/active_rulebook.json"),
                Path("engine3/rulebook/active_rulebook.json"),
                Path(__file__).parents[3] / "rulebook" / "active_rulebook.json",
            ]
            for c in candidates:
                if c.exists():
                    rulebook_path = c
                    break
            if rulebook_path is None:
                rulebook_path = Path("rulebook/active_rulebook.json")

        if inventory_dir is None:
            candidates = [
                Path("vendor/pathfinding.cloud/data/paths/aws"),
                Path("engine3/vendor/pathfinding.cloud/data/paths/aws"),
                Path(__file__).parents[3] / "vendor" / "pathfinding.cloud" / "data" / "paths" / "aws",
            ]
            for c in candidates:
                if c.exists():
                    inventory_dir = c
                    break
            if inventory_dir is None:
                inventory_dir = Path("vendor/pathfinding.cloud/data/paths/aws")

        self.rulebook_path = Path(rulebook_path)
        self.inventory_dir = Path(inventory_dir)

        self.rule_id_to_module: dict[str, str] = {}
        self.action_to_modules: dict[str, set[str]] = {}
        self.action_conflicts: dict[str, list[str]] = {}
        self.real_modules_on_disk: set[str] = set()

        self._load_inventory()
        self._build_indexes()

    def _load_inventory(self) -> None:
        """Discovers all real YAML module definitions on disk."""
        if self.inventory_dir.exists():
            for yaml_file in self.inventory_dir.rglob("*.yaml"):
                # Module ID corresponds to the YAML filename stem (e.g., iam-001.yaml -> iam-001)
                self.real_modules_on_disk.add(yaml_file.stem)

    def _build_indexes(self) -> None:
        """Builds primary (rule_id) and secondary (action) indexes from active_rulebook.json."""
        if not self.rulebook_path.exists():
            return

        with open(self.rulebook_path, "r", encoding="utf-8") as f:
            rules_raw = json.load(f)

        for r in rules_raw:
            rule_id = r.get("rule_id", "")
            source_path_id = r.get("source_path_id") or r.get("extras", {}).get("source_path_id")
            action = r.get("action", "")

            if source_path_id:
                self.rule_id_to_module[rule_id] = str(source_path_id).strip()

                if action:
                    act_clean = action.lower().strip()
                    self.action_to_modules.setdefault(act_clean, set()).add(str(source_path_id).strip())

        # Detect action conflicts
        for act, mod_set in self.action_to_modules.items():
            if len(mod_set) > 1:
                self.action_conflicts[act] = sorted(list(mod_set))

    def resolve_by_rule_id(self, rule_id: str | None) -> str | None:
        """Primary index lookup: Unambiguous direct resolution by rule_id."""
        if not rule_id:
            return None
        return self.rule_id_to_module.get(rule_id)

    def resolve_by_action(self, action: str | list[str]) -> str | None:
        """Secondary index lookup: Action-based resolution."""
        if isinstance(action, list):
            for a in action:
                res = self.resolve_by_action(a)
                if res:
                    return res
            return None

        act_clean = action.lower().strip()
        mod_set = self.action_to_modules.get(act_clean)
        if not mod_set:
            return None

        if len(mod_set) == 1:
            return next(iter(mod_set))

        # Conflict present: return canonical primary match or first sorted
        return sorted(list(mod_set))[0]

    def resolve_hop(self, matched_rule_id: str | None, action: str | list[str]) -> str | None:
        """Resolves module ID using primary rule_id lookup first, falling back to action index."""
        if matched_rule_id:
            mod_id = self.resolve_by_rule_id(matched_rule_id)
            if mod_id:
                return mod_id
        return self.resolve_by_action(action)

    def get_stats(self) -> ModuleResolutionStats:
        """Evaluates resolution coverage against real on-disk modules."""
        with open(self.rulebook_path, "r", encoding="utf-8") as f:
            rules_raw = json.load(f)

        resolved_list: list[tuple[str, str, str]] = []
        missing_on_disk_list: list[tuple[str, str, str, str]] = []
        no_id_list: list[tuple[str, str, str]] = []

        for r in rules_raw:
            rule_id = r.get("rule_id", "")
            action = r.get("action", "")
            title = r.get("title", "")
            source_path_id = r.get("source_path_id") or r.get("extras", {}).get("source_path_id")

            if not source_path_id:
                no_id_list.append((rule_id, action, "No source_path_id in rule definition"))
            elif source_path_id in self.real_modules_on_disk:
                resolved_list.append((rule_id, action, source_path_id))
            else:
                missing_on_disk_list.append((
                    rule_id,
                    action,
                    source_path_id,
                    f"Module '{source_path_id}' is defined as target goal/data rule, not in pathfinding.cloud privesc inventory",
                ))

        return ModuleResolutionStats(
            total_rules=len(rules_raw),
            resolved_to_disk=len(resolved_list),
            id_missing_on_disk=len(missing_on_disk_list),
            no_id_present=len(no_id_list),
            action_conflicts=self.action_conflicts,
            resolved_list=resolved_list,
            missing_on_disk_list=missing_on_disk_list,
            no_id_list=no_id_list,
        )


__all__ = [
    "ModuleResolutionStats",
    "PathrunnerModuleResolver",
]
