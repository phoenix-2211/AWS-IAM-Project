from typing import ClassVar

from pydantic import BaseModel, Field

from engine3.contracts.models import Rule
from engine3.stages.s2_path import CandidatePath


class QueuedPath(BaseModel):
    queue_rank: int
    path_id: str
    source_tree: str = "unknown"
    severity: str = "LOW"
    status: str = "SANDBOX_FAILED"
    queue_reason: str
    sandbox_group_key: str = "NOT_MAPPED"
    path: CandidatePath


class Stage3QueueResult(BaseModel):
    queue: list[QueuedPath] = Field(default_factory=list)
    total_paths: int = 0
    message: str = ""


class Stage3Prioritizer:
    """Stage 3 Queue Prioritizer."""

    SEVERITY_WEIGHTS: ClassVar[dict[str, int]] = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }

    def prioritize_paths(
        self, paths: list[CandidatePath], active_rules: list[Rule], source_tree: str = "unknown"
    ) -> Stage3QueueResult:
        if not paths:
            return Stage3QueueResult(
                queue=[], total_paths=0, message="No candidate paths to queue."
            )

        rule_sev_map: dict[str, str] = {r.rule_id: r.severity for r in active_rules}

        def get_max_severity(path: CandidatePath) -> str:
            max_w = 0
            best_sev = "LOW"
            for h in path.hops:
                if h.matched_rule_id and h.matched_rule_id in rule_sev_map:
                    sev = rule_sev_map[h.matched_rule_id]
                    w = self.SEVERITY_WEIGHTS.get(sev, 1)
                    if w > max_w:
                        max_w = w
                        best_sev = sev
            return best_sev

        def sort_key(path: CandidatePath):
            max_sev = get_max_severity(path)
            sev_w = self.SEVERITY_WEIGHTS.get(max_sev, 1)
            hop_count = len(path.hops)
            assumption_count = len(path.assumptions)
            return (-sev_w, hop_count, assumption_count, path.path_id)

        sorted_paths = sorted(paths, key=sort_key)
        queued: list[QueuedPath] = []

        for rank, p in enumerate(sorted_paths, start=1):
            max_sev = get_max_severity(p)
            hop_c = len(p.hops)
            assump_c = len(p.assumptions)
            reason = f"severity {max_sev}, {hop_c} hops, {assump_c} assumption{'s' if assump_c != 1 else ''}"

            queued.append(
                QueuedPath(
                    queue_rank=rank,
                    path_id=p.path_id,
                    source_tree=source_tree,
                    severity=max_sev,
                    status="SANDBOX_FAILED",
                    queue_reason=reason,
                    sandbox_group_key="NOT_MAPPED",
                    path=p,
                )
            )

        return Stage3QueueResult(
            queue=queued, total_paths=len(queued), message="Queue successfully generated."
        )
