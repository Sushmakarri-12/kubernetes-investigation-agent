"""
Evidence extractor and correlator for Kubernetes log investigation.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from .models import EvidenceItem, Finding, LogEntry, Severity
from .rules import InvestigationRule, get_default_rules


class EvidenceExtractor:
    """Extracts, contextualizes, and groups log evidence for investigation."""

    def __init__(
        self,
        rules: Optional[List[InvestigationRule]] = None,
        context_window: int = 1,
    ):
        self.rules = rules if rules is not None else get_default_rules()
        self.context_window = max(0, context_window)

    def extract_evidence(
        self, entries: List[LogEntry]
    ) -> Tuple[List[EvidenceItem], List[Finding]]:
        """Scans log entries, matches against rules, and aggregates into findings with evidence."""
        raw_evidence_list: List[Tuple[EvidenceItem, InvestigationRule]] = []
        n = len(entries)

        # 1. Match each entry against rules
        for i, entry in enumerate(entries):
            # Check message or raw_text
            text_to_check = entry.message
            for rule in self.rules:
                match = rule.matches(text_to_check)
                if not match and entry.raw_text != entry.message:
                    match = rule.matches(entry.raw_text)

                if match:
                    # Gather context lines
                    before_start = max(0, i - self.context_window)
                    after_end = min(n, i + 1 + self.context_window)

                    context_before = [entries[idx].raw_text for idx in range(before_start, i)]
                    context_after = [entries[idx].raw_text for idx in range(i + 1, after_end)]

                    evidence_id = f"EV-{len(raw_evidence_list) + 1:04d}"
                    desc = f"{rule.title}: matched '{match.group(0)}'"

                    item = EvidenceItem(
                        evidence_id=evidence_id,
                        line_number=entry.line_number,
                        raw_log=entry.raw_text,
                        category=rule.category,
                        description=desc,
                        severity=rule.severity,
                        timestamp=entry.timestamp,
                        context_before=context_before,
                        context_after=context_after,
                    )
                    raw_evidence_list.append((item, rule))

        # 2. Group evidence into Findings
        grouped_by_rule: Dict[str, List[EvidenceItem]] = defaultdict(list)
        rule_map: Dict[str, InvestigationRule] = {}

        for item, rule in raw_evidence_list:
            grouped_by_rule[rule.rule_id].append(item)
            rule_map[rule.rule_id] = rule

        findings: List[Finding] = []
        for rule_id, evidence_items in grouped_by_rule.items():
            rule = rule_map[rule_id]
            timestamps = [e.timestamp for e in evidence_items if e.timestamp]
            first_seen = timestamps[0] if timestamps else None
            last_seen = timestamps[-1] if timestamps else None

            # Generate consolidated description
            desc = (
                f"{rule.description_template} "
                f"Detected {len(evidence_items)} occurrence(s) in analyzed logs."
            )

            finding = Finding(
                category=rule.category,
                title=rule.title,
                severity=rule.severity,
                confidence=rule.confidence,
                description=desc,
                evidence=evidence_items,
                occurrence_count=len(evidence_items),
                first_seen=first_seen,
                last_seen=last_seen,
            )
            findings.append(finding)

        # Sort findings by severity descending (CRITICAL -> HIGH -> MEDIUM -> LOW)
        findings.sort(key=lambda f: (f.severity.rank, f.occurrence_count), reverse=True)

        all_evidence = [item for item, _ in raw_evidence_list]
        return all_evidence, findings
