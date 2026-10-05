"""
Main Kubernetes Investigation Agent orchestrator.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import List, Optional, Union

from .analyzer import InvestigationAnalyzer
from .evidence import EvidenceExtractor
from .formatters import render_markdown, render_terminal
from .llm import LLMAugmentedReasoner
from .models import InvestigationReport, LogEntry
from .parser import LogParser
from .rules import InvestigationRule


class KubernetesInvestigationAgent:
    """Agent that performs automated investigation on Kubernetes logs and generates detailed evidence-backed reports."""

    def __init__(
        self,
        rules: Optional[List[InvestigationRule]] = None,
        context_window: int = 1,
        enable_llm: bool = False,
        llm_api_key: Optional[str] = None,
        llm_model: str = "gemini-2.5-flash",
    ):
        self.parser = LogParser()
        self.extractor = EvidenceExtractor(rules=rules, context_window=context_window)
        self.analyzer = InvestigationAnalyzer()
        self.enable_llm = enable_llm
        self.llm = LLMAugmentedReasoner(api_key=llm_api_key, model=llm_model)

    def investigate(self, logs: Union[str, Path, io.TextIOBase]) -> InvestigationReport:
        """Main investigation entrypoint accepting a raw log string, Path, or file-like object."""
        if isinstance(logs, Path):
            return self.investigate_file(logs)
        elif isinstance(logs, str):
            # Check if string is an existing file path
            path_obj = Path(logs)
            if path_obj.is_file():
                return self.investigate_file(path_obj)
            return self.investigate_text(logs)
        elif hasattr(logs, "read"):
            content = logs.read()
            return self.investigate_text(content)
        else:
            raise ValueError(f"Unsupported log input type: {type(logs)}")

    def investigate_file(self, file_path: Union[str, Path]) -> InvestigationReport:
        """Investigates logs from a file on disk."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {path}")

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        entries = self.parser.parse_lines(lines)
        return self._run_investigation_pipeline(entries, raw_text="".join(lines[:100]))

    def investigate_text(self, text: str) -> InvestigationReport:
        """Investigates a raw string of logs."""
        entries = self.parser.parse_text(text)
        return self._run_investigation_pipeline(entries, raw_text=text[:2000])

    def investigate_entries(self, entries: List[LogEntry]) -> InvestigationReport:
        """Investigates an already parsed list of LogEntry items."""
        return self._run_investigation_pipeline(entries, raw_text="")

    def _run_investigation_pipeline(
        self, entries: List[LogEntry], raw_text: str = ""
    ) -> InvestigationReport:
        # Phase 1: Extract evidence and identify findings
        evidence, findings = self.extractor.extract_evidence(entries)

        # Phase 2: Core analysis (root cause, timeline, remediations)
        report = self.analyzer.analyze(entries, evidence, findings)

        # Phase 3: Optional LLM augmentation
        if self.enable_llm and self.llm.is_available:
            enriched_root_cause = self.llm.enrich_analysis(
                raw_logs_snippet=raw_text,
                findings=findings,
                evidence=evidence,
                base_root_cause=report.root_cause,
            )
            if enriched_root_cause:
                report.root_cause = enriched_root_cause

        return report

    def render_markdown(self, report: InvestigationReport) -> str:
        return render_markdown(report)

    def render_terminal(self, report: InvestigationReport, color: bool = True) -> str:
        return render_terminal(report, color=color)
