"""
Formatters for investigation reports (Markdown, Terminal text, JSON).
"""

from __future__ import annotations

from typing import Optional

from .models import InvestigationReport, Severity

# ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"
GRAY = "\033[90m"


def render_markdown(report: InvestigationReport) -> str:
    """Renders the investigation report into comprehensive Markdown with supporting evidence."""
    lines = []

    # Title & Metadata
    lines.append("# 🔍 Kubernetes Log Investigation Report\n")

    sev_badge = {
        Severity.CRITICAL: "🔴 **CRITICAL**",
        Severity.HIGH: "🟠 **HIGH**",
        Severity.MEDIUM: "🟡 **MEDIUM**",
        Severity.LOW: "🔵 **LOW**",
        Severity.INFO: "🟢 **INFO**",
    }.get(report.overall_severity, report.overall_severity.value)

    lines.append("| Property | Details |")
    lines.append("|---|---|")
    lines.append(f"| **Overall Incident Severity** | {sev_badge} |")
    lines.append(f"| **Target Workload / Pod** | `{report.target_workload or 'Auto-detected / Cluster-wide'}` |")
    lines.append(f"| **Namespace** | `{report.namespace or 'default'}` |")
    lines.append(f"| **Total Log Lines Analyzed** | {report.total_lines_analyzed} |")
    lines.append(f"| **Time Window** | `{report.time_window[0] or 'N/A'}` to `{report.time_window[1] or 'N/A'}` |")
    lines.append(f"| **Identified Findings** | {len(report.findings)} |")
    lines.append(f"| **Supporting Evidence Count** | {len(report.evidence)} log item(s) |")
    lines.append("\n---\n")

    # Executive Summary
    lines.append("## 📋 Executive Summary\n")
    lines.append(f"> {report.summary}\n")

    # Root Cause Analysis
    if report.root_cause:
        lines.append("## 🎯 Root Cause Analysis (RCA)\n")
        lines.append(f"- **Primary Root Cause:** **{report.root_cause.primary_cause}**")
        lines.append(f"- **Confidence Score:** `{report.root_cause.confidence * 100:.1f}%`")
        lines.append(f"- **Explanation:** {report.root_cause.explanation}\n")

        if report.root_cause.causal_chain:
            lines.append("### Causal Chain of Events")
            for step in report.root_cause.causal_chain:
                lines.append(f"- {step}")
            lines.append("")

    # Detailed Findings
    if report.findings:
        lines.append("## ⚠️ Key Findings & Symptoms\n")
        for idx, finding in enumerate(report.findings, start=1):
            lines.append(f"### {idx}. {finding.title} (`{finding.category}`)")
            lines.append(f"- **Severity:** `{finding.severity.value}`")
            lines.append(f"- **Occurrences:** `{finding.occurrence_count}`")
            if finding.first_seen and finding.last_seen:
                lines.append(f"- **Span:** `{finding.first_seen}` → `{finding.last_seen}`")
            lines.append(f"- **Description:** {finding.description}\n")

    # Supporting Evidence
    lines.append("## 📑 Supporting Evidence\n")
    if not report.evidence:
        lines.append("_No abnormal evidence entries matched configured investigation signatures._\n")
    else:
        lines.append("The following log lines serve as direct evidence for the findings above:\n")
        for ev in report.evidence:
            lines.append(f"#### Evidence `[{ev.evidence_id}]` — Line {ev.line_number} ({ev.category})")
            if ev.timestamp:
                lines.append(f"**Timestamp:** `{ev.timestamp}`  ")
            lines.append(f"**Observation:** {ev.description}\n")

            # Context block
            lines.append("```log")
            for c_before in ev.context_before:
                lines.append(f"  {c_before}")
            lines.append(f"> {ev.raw_log.strip()}  <-- [Trigger]")
            for c_after in ev.context_after:
                lines.append(f"  {c_after}")
            lines.append("```\n")

    # Incident Timeline
    if report.timeline:
        lines.append("## ⏱️ Chronological Incident Timeline\n")
        lines.append("| Line | Timestamp | Event Category | Observation |")
        lines.append("|---|---|---|---|")
        for item in report.timeline:
            line_str = f"L{item['line']}"
            ts_str = f"`{item['timestamp']}`"
            cat_str = f"`{item['category']}`"
            ev_str = item["event"].replace("|", "\\|")
            lines.append(f"| {line_str} | {ts_str} | {cat_str} | {ev_str} |")
        lines.append("\n")

    # Remediation Plan
    if report.remediations:
        lines.append("## 🛠️ Actionable Remediation Plan\n")
        lines.append("Follow these prioritized operational and preventative measures:\n")

        for idx, step in enumerate(report.remediations, start=1):
            type_tag = step.step_type.upper()
            lines.append(f"### Step {idx} [{type_tag}]: {step.action}\n")
            lines.append(f"{step.explanation}\n")
            if step.command:
                lines.append("```bash")
                lines.append(step.command)
                lines.append("```\n")

    return "\n".join(lines)


def render_terminal(report: InvestigationReport, color: bool = True) -> str:
    """Renders a high-visibility terminal summary for the CLI."""
    c_red = RED if color else ""
    c_green = GREEN if color else ""
    c_yellow = YELLOW if color else ""
    c_blue = BLUE if color else ""
    c_cyan = CYAN if color else ""
    c_bold = BOLD if color else ""
    c_reset = RESET if color else ""
    c_gray = GRAY if color else ""

    sev_color = {
        Severity.CRITICAL: c_red,
        Severity.HIGH: c_red,
        Severity.MEDIUM: c_yellow,
        Severity.LOW: c_blue,
        Severity.INFO: c_green,
    }.get(report.overall_severity, "")

    buf = []
    buf.append(f"\n{c_bold}════════════════════════════════════════════════════════════════════════════════{c_reset}")
    buf.append(f"{c_bold}  KUBERNETES LOG INVESTIGATION AGENT REPORT{c_reset}")
    buf.append(f"{c_bold}════════════════════════════════════════════════════════════════════════════════{c_reset}")

    buf.append(f"  {c_bold}Incident Severity:{c_reset} {sev_color}{c_bold}{report.overall_severity.value}{c_reset}")
    buf.append(f"  {c_bold}Target Workload:  {c_reset} {report.target_workload or 'Cluster-wide / Unknown'}")
    buf.append(f"  {c_bold}Namespace:        {c_reset} {report.namespace or 'default'}")
    buf.append(f"  {c_bold}Lines Analyzed:   {c_reset} {report.total_lines_analyzed}")
    buf.append(f"  {c_bold}Evidence Count:   {c_reset} {len(report.evidence)} log entries")
    buf.append(f"────────────────────────────────────────────────────────────────────────────────")

    buf.append(f"{c_bold}📋 SUMMARY:{c_reset}")
    buf.append(f"  {report.summary}\n")

    if report.root_cause:
        buf.append(f"{c_bold}🎯 ROOT CAUSE ANALYSIS:{c_reset}")
        buf.append(f"  • {c_bold}Primary Cause:{c_reset} {report.root_cause.primary_cause}")
        buf.append(f"  • {c_bold}Confidence:   {c_reset} {report.root_cause.confidence * 100:.1f}%")
        buf.append(f"  • {c_bold}Explanation:  {c_reset} {report.root_cause.explanation}")
        if report.root_cause.causal_chain:
            buf.append(f"  • {c_bold}Causal Chain:{c_reset}")
            for step in report.root_cause.causal_chain:
                buf.append(f"      {step}")
        buf.append("")

    if report.evidence:
        buf.append(f"{c_bold}📑 KEY EVIDENCE SNIPPETS ({len(report.evidence)} total):{c_reset}")
        for ev in report.evidence[:5]:
            buf.append(f"  [{c_cyan}{ev.evidence_id}{c_reset}] Line {ev.line_number}: {c_yellow}{ev.description}{c_reset}")
            buf.append(f"    {c_gray}> {ev.raw_log.strip()}{c_reset}")
        if len(report.evidence) > 5:
            buf.append(f"    {c_gray}... and {len(report.evidence) - 5} more evidence items.{c_reset}")
        buf.append("")

    if report.remediations:
        buf.append(f"{c_bold}🛠️ RECOMMENDED REMEDIATION STEPS:{c_reset}")
        for idx, rem in enumerate(report.remediations[:4], start=1):
            buf.append(f"  {idx}. [{rem.step_type.upper()}] {rem.action}")
            if rem.command:
                buf.append(f"     {c_green}$ {rem.command}{c_reset}")
        buf.append("")

    buf.append(f"{c_bold}════════════════════════════════════════════════════════════════════════════════{c_reset}\n")
    return "\n".join(buf)
