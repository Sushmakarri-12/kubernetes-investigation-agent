"""
Investigation analysis and root cause synthesis engine.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .models import (
    EvidenceItem,
    Finding,
    InvestigationReport,
    LogEntry,
    RemediationStep,
    RootCause,
    Severity,
)
from .rules import get_default_rules

# Causal hierarchy: higher priority causes explain lower priority symptoms
CAUSAL_PRIORITY = {
    "STORAGE_VOLUME": 100,        # Volume unmounted/broken prevents container start
    "IMAGE_PULL_FAILURE": 95,      # Cannot pull container image
    "MEMORY_EXHAUSTION": 92,      # OOM killer terminates container
    "APPLICATION_EXCEPTION": 88,  # Fatal panic / uncaught exception crashes container
    "RESOURCE_EXHAUSTION": 85,    # Thread pool or connection exhaustion
    "RBAC_AUTHORIZATION": 80,     # K8s API 403 Forbidden halts operator/controller
    "DNS_FAILURE": 75,            # DNS cannot resolve service
    "NETWORK_CONNECTIVITY": 70,   # Network dropped / connection refused
    "PROBE_FAILURE": 50,          # Probe failed (almost always a symptom of dead/frozen app)
    "CRASH_LOOP": 40,             # Consequence of prior crashes
}


class InvestigationAnalyzer:
    """Performs deep investigation, root cause synthesis, and timeline construction."""

    def __init__(self):
        self.default_rules = {r.rule_id: r for r in get_default_rules()}

    def analyze(
        self,
        entries: List[LogEntry],
        evidence: List[EvidenceItem],
        findings: List[Finding],
    ) -> InvestigationReport:
        # Determine overall severity
        overall_severity = Severity.INFO
        if findings:
            overall_severity = findings[0].severity  # sorted descending

        # Extract workload metadata
        workloads = [e.pod_name for e in entries if e.pod_name]
        target_workload = workloads[0] if workloads else None

        namespaces = [e.namespace for e in entries if e.namespace]
        target_namespace = namespaces[0] if namespaces else None

        # Determine time window
        timestamps = [e.timestamp for e in entries if e.timestamp]
        time_window = (
            timestamps[0] if timestamps else None,
            timestamps[-1] if timestamps else None,
        )

        # Build timeline
        timeline = self._build_timeline(evidence)

        # Synthesize Root Cause
        root_cause = self._synthesize_root_cause(findings, evidence)

        # Aggregate remediations
        remediations = self._aggregate_remediations(findings, root_cause)

        # Generate summary
        summary = self._generate_summary(
            overall_severity, findings, root_cause, target_workload, len(entries)
        )

        return InvestigationReport(
            summary=summary,
            overall_severity=overall_severity,
            total_lines_analyzed=len(entries),
            target_workload=target_workload,
            namespace=target_namespace,
            time_window=time_window,
            root_cause=root_cause,
            findings=findings,
            evidence=evidence,
            timeline=timeline,
            remediations=remediations,
        )

    def _build_timeline(self, evidence: List[EvidenceItem]) -> List[Dict[str, Any]]:
        timeline: List[Dict[str, Any]] = []
        for item in evidence:
            timeline.append({
                "line": item.line_number,
                "timestamp": item.timestamp or "N/A",
                "category": item.category,
                "event": item.description,
                "raw": item.raw_log.strip(),
            })
        return timeline

    def _synthesize_root_cause(
        self, findings: List[Finding], evidence: List[EvidenceItem]
    ) -> Optional[RootCause]:
        if not findings:
            return RootCause(
                primary_cause="No anomalous Kubernetes failure patterns detected",
                explanation="The analyzed logs do not contain critical crash, timeout, or resource exhaustion indicators.",
                confidence=0.85,
                causal_chain=["Logs analyzed", "Standard operating levels observed"],
                key_evidence=[],
            )

        # Select highest-priority causal finding
        sorted_findings = sorted(
            findings,
            key=lambda f: CAUSAL_PRIORITY.get(f.category, 0),
            reverse=True,
        )
        primary_finding = sorted_findings[0]

        causal_chain = self._construct_causal_chain(primary_finding, findings)
        key_evidence = primary_finding.evidence[:3]

        return RootCause(
            primary_cause=f"{primary_finding.title} ({primary_finding.category})",
            explanation=primary_finding.description,
            confidence=primary_finding.confidence,
            causal_chain=causal_chain,
            key_evidence=key_evidence,
        )

    def _construct_causal_chain(
        self, primary: Finding, all_findings: List[Finding]
    ) -> List[str]:
        chain: List[str] = []
        categories = {f.category for f in all_findings}

        if primary.category == "MEMORY_EXHAUSTION":
            chain.append("1. Workload memory usage continuously surged, reaching cgroup resource limits.")
            chain.append("2. Linux kernel OOM Killer triggered SIGKILL (Exit Code 137).")
            if "PROBE_FAILURE" in categories:
                chain.append("3. Subsequent health probes timed out or were refused due to terminated application process.")
            if "CRASH_LOOP" in categories:
                chain.append("4. Kubelet entered CrashLoopBackOff with exponential restart delay.")
        elif primary.category == "IMAGE_PULL_FAILURE":
            chain.append("1. Kubelet attempted to pull specified container image from registry.")
            chain.append("2. Registry rejected request (missing image tag, 401/403 authorization failure, or rate limit).")
            chain.append("3. Pod remained in ImagePullBackOff / ErrImagePull state; container never initialized.")
        elif primary.category == "STORAGE_VOLUME":
            chain.append("1. Volume attachment or mount operation failed (multi-attach lock or disk full).")
            chain.append("2. Kubelet could not mount container rootfs/subpath.")
            chain.append("3. Pod stuck in ContainerCreating or failing initialization.")
        elif primary.category == "RBAC_AUTHORIZATION":
            chain.append("1. Pod ServiceAccount attempted to query or modify Kubernetes API resources.")
            chain.append("2. Kubernetes API Server returned 403 Forbidden due to absent RoleBinding/ClusterRole.")
            chain.append("3. Application crashed or halted critical controller sync loop.")
        elif primary.category == "DNS_FAILURE":
            chain.append("1. Pod sent DNS query to cluster CoreDNS.")
            chain.append("2. CoreDNS failed to resolve hostname (timeout / SERVFAIL).")
            chain.append("3. Workload failed to establish connection to upstream database or service.")
        elif primary.category == "NETWORK_CONNECTIVITY":
            chain.append("1. Workload attempted outbound connection to external or internal service endpoint.")
            chain.append("2. Connection was refused or timed out (NetworkPolicy drop or offline target).")
            chain.append("3. Downstream requests failed with HTTP 502/504 or application errors.")
        elif primary.category == "APPLICATION_EXCEPTION":
            chain.append("1. Application encountered an unhandled exception, fatal panic, or segfault.")
            chain.append("2. Main process exited with non-zero status.")
            if "CRASH_LOOP" in categories:
                chain.append("3. Kubelet placed container into CrashLoopBackOff.")
        else:
            chain.append(f"1. Primary incident trigger: {primary.title}.")
            step_idx = 2
            for f in all_findings:
                if f != primary:
                    chain.append(f"{step_idx}. Cascading symptom: {f.title}.")
                    step_idx += 1

        return chain

    def _aggregate_remediations(
        self, findings: List[Finding], root_cause: Optional[RootCause]
    ) -> List[RemediationStep]:
        remediations: List[RemediationStep] = []
        seen_actions = set()

        # Gather remediations from matched rules
        for finding in findings:
            for rule in self.default_rules.values():
                if rule.category == finding.category or rule.title == finding.title:
                    for rem in rule.remediations:
                        if rem.action not in seen_actions:
                            seen_actions.add(rem.action)
                            remediations.append(rem)

        # Sort immediate -> diagnostic -> architectural
        order = {"immediate": 0, "diagnostic": 1, "architectural": 2}
        remediations.sort(key=lambda r: order.get(r.step_type, 3))
        return remediations

    def _generate_summary(
        self,
        severity: Severity,
        findings: List[Finding],
        root_cause: Optional[RootCause],
        workload: Optional[str],
        total_lines: int,
    ) -> str:
        target = f"for workload '{workload}'" if workload else "across analyzed Kubernetes container logs"
        if not findings or not root_cause:
            return f"Investigation completed {target}. Scanned {total_lines} lines; no critical failures or anomalies were detected."

        primary_title = root_cause.primary_cause
        finding_count = len(findings)
        return (
            f"Investigation identified a {severity.value} severity incident {target}. "
            f"Analyzed {total_lines} log entries and discovered {finding_count} distinct finding(s). "
            f"The primary root cause is '{primary_title}'. "
            f"Immediate remediation and diagnostic actions are required to restore service stability."
        )
