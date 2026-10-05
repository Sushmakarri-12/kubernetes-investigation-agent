"""
Domain models for Kubernetes log investigation.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        levels = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return levels.get(self, 0)

    def __ge__(self, other: Severity) -> bool:
        if isinstance(other, Severity):
            return self.rank >= other.rank
        return NotImplemented

    def __gt__(self, other: Severity) -> bool:
        if isinstance(other, Severity):
            return self.rank > other.rank
        return NotImplemented

    def __le__(self, other: Severity) -> bool:
        if isinstance(other, Severity):
            return self.rank <= other.rank
        return NotImplemented

    def __lt__(self, other: Severity) -> bool:
        if isinstance(other, Severity):
            return self.rank < other.rank
        return NotImplemented


@dataclass
class LogEntry:
    """Represents a single parsed log line."""
    line_number: int
    raw_text: str
    message: str
    timestamp: Optional[str] = None
    level: str = "INFO"
    pod_name: Optional[str] = None
    namespace: Optional[str] = None
    container: Optional[str] = None
    stream: Optional[str] = None  # stdout / stderr
    is_json: bool = False
    structured_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceItem:
    """A concrete piece of log evidence supporting a finding."""
    evidence_id: str
    line_number: int
    raw_log: str
    category: str
    description: str
    severity: Severity
    timestamp: Optional[str] = None
    context_before: List[str] = field(default_factory=list)
    context_after: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class Finding:
    """An identified issue or symptom with associated evidence."""
    category: str
    title: str
    severity: Severity
    confidence: float  # 0.0 - 1.0
    description: str
    evidence: List[EvidenceItem] = field(default_factory=list)
    occurrence_count: int = 1
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["evidence"] = [e.to_dict() for e in self.evidence]
        return data


@dataclass
class RootCause:
    """The synthesized primary root cause and causal chain."""
    primary_cause: str
    explanation: str
    confidence: float
    causal_chain: List[str] = field(default_factory=list)
    key_evidence: List[EvidenceItem] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["key_evidence"] = [e.to_dict() for e in self.key_evidence]
        return data


@dataclass
class RemediationStep:
    """Recommended operational command or architectural fix."""
    action: str
    explanation: str
    step_type: str  # "immediate", "diagnostic", "architectural"
    command: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationReport:
    """Complete diagnostic report for a Kubernetes log investigation."""
    summary: str
    overall_severity: Severity
    total_lines_analyzed: int
    target_workload: Optional[str] = None
    namespace: Optional[str] = None
    time_window: Tuple[Optional[str], Optional[str]] = (None, None)
    root_cause: Optional[RootCause] = None
    findings: List[Finding] = field(default_factory=list)
    evidence: List[EvidenceItem] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    remediations: List[RemediationStep] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary,
            "overall_severity": self.overall_severity.value,
            "total_lines_analyzed": self.total_lines_analyzed,
            "target_workload": self.target_workload,
            "namespace": self.namespace,
            "time_window": {
                "start": self.time_window[0],
                "end": self.time_window[1],
            },
            "root_cause": self.root_cause.to_dict() if self.root_cause else None,
            "findings": [f.to_dict() for f in self.findings],
            "evidence_count": len(self.evidence),
            "evidence": [e.to_dict() for e in self.evidence],
            "timeline": self.timeline,
            "remediations": [r.to_dict() for r in self.remediations],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_markdown(self) -> str:
        from .formatters import render_markdown
        return render_markdown(self)
