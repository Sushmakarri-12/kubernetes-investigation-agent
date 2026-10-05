# ☸️ Kubernetes Log Investigation Agent in Python

A lightweight, zero-dependency Kubernetes incident investigation agent in Python. It ingests raw or structured container logs, performs automated forensic analysis to detect Kubernetes-specific failure modes, extracts exact supporting log evidence with surrounding context, determines the primary root cause and causal chain, and generates an actionable remediation plan.

---

## 🌟 Key Features

- **Multi-Format Kubernetes Log Ingestion**:
  - Container runtime formats (CRI-O / containerd timestamps with stdout/stderr streams).
  - Kubelet & system klog format (`E1004 12:00:00.123456 ...`).
  - Structured JSON logs (Zap, Winston, Logrus, Python structlog).
  - Plain stdout/stderr logs.
- **Deep Kubernetes Heuristic & Rule Engine**:
  - `OOMKilled` (Exit Code 137, cgroup limits, Java/Node heap out of memory).
  - `CrashLoopBackOff` & container restart loops.
  - Liveness & Readiness probe timeouts / connection refused.
  - `ImagePullBackOff` & `ErrImagePull` (missing tags, 401/403 auth, rate limits).
  - CoreDNS lookup failures & inter-service network partition/timeouts.
  - RBAC authorization failures (`403 Forbidden` for ServiceAccounts).
  - Storage & PVC mount failures (disk pressure, multi-attach locks).
  - Unhandled application panics, segfaults (Exit Code 139), and uncaught exceptions.
  - Thread pool and database connection pool exhaustion.
- **Evidence-Backed Analysis**:
  - Extracts exact line numbers, timestamps, raw log snippets, and surrounding context.
  - Highlights the trigger event against adjacent context lines.
- **Causal Root Cause Analysis (RCA)**:
  - Distinguishes primary root causes from downstream symptoms (e.g. Memory leak $\to$ OOM Kill $\to$ Container crash $\to$ Readiness probe failure $\to$ CrashLoopBackOff).
- **Prioritized Actionable Remediations**:
  - Direct `kubectl` commands ready to run for immediate relief, diagnostic checks, and architectural fixes.
- **Flexible Output**:
  - Interactive ANSI-colored terminal report.
  - Comprehensive GitHub-flavored Markdown report.
  - Machine-readable JSON output for CI/CD or automated webhook alerts.
- **Zero Mandatory Dependencies**:
  - Runs out of the box with standard Python 3.9+.
  - Optional AI augmentation with Gemini (`GEMINI_API_KEY`) via standard library HTTP.

---

## 📁 Project Structure

```
├── k8s_agent/
│   ├── __init__.py           # Package exports
│   ├── models.py             # LogEntry, EvidenceItem, Finding, RootCause, Report models
│   ├── parser.py             # Log parser (CRI, klog, JSON, ISO)
│   ├── rules.py              # Kubernetes failure detection rules & signatures
│   ├── evidence.py           # Evidence extraction & context aggregator
│   ├── analyzer.py           # RCA causal chain synthesizer & timeline generator
│   ├── agent.py              # KubernetesInvestigationAgent orchestrator
│   ├── formatters.py         # Markdown, Terminal, and JSON formatters
│   ├── llm.py                # Optional Gemini LLM augmentation layer
│   └── cli.py                # CLI interface
├── sample_logs/
│   ├── oom_killed.log        # Memory limit exceeded & OOM kill scenario
│   ├── crashloop_probe.log   # Liveness/Readiness probe failure scenario
│   ├── dns_network_failure.log # CoreDNS lookup failure scenario
│   ├── rbac_permission_denied.log # ServiceAccount RBAC 403 Forbidden scenario
│   └── json_microservice_crash.log # Structured JSON panic & pool exhaustion
├── tests/
│   ├── test_parser.py        # Parser unit tests
│   ├── test_rules.py         # Heuristic pattern matching tests
│   └── test_agent.py         # End-to-end integration tests
├── main.py                   # Root CLI executable
└── README.md                 # Documentation
```

---

## 🚀 Quick Start (CLI)

### 1. Run Built-in Incident Demos
```bash
# OOMKilled scenario
python3 main.py --demo oom

# Probe failure & CrashLoopBackOff scenario
python3 main.py --demo probe

# CoreDNS failure scenario
python3 main.py --demo dns

# RBAC permission denied scenario
python3 main.py --demo rbac

# JSON microservice crash scenario
python3 main.py --demo json
```

### 2. Investigate a Kubernetes Log File
```bash
python3 main.py path/to/pod.log
```

### 3. Investigate from Stdin or `kubectl logs`
```bash
kubectl logs my-pod --previous | python3 main.py
```

### 4. Export as Markdown or JSON
```bash
# Save detailed Markdown report to a file
python3 main.py sample_logs/oom_killed.log --format markdown -o investigation_report.md

# Output JSON for CI/CD or webhook integration
python3 main.py sample_logs/oom_killed.log --format json
```

---

## 🐍 Python API Usage

You can embed `KubernetesInvestigationAgent` directly into your Python automation scripts, incident bots, or monitoring pipelines:

```python
from k8s_agent import KubernetesInvestigationAgent

# Initialize the agent
agent = KubernetesInvestigationAgent(context_window=1)

# Option A: Investigate from a file path
report = agent.investigate_file("sample_logs/oom_killed.log")

# Option B: Investigate from a raw string or stream
# report = agent.investigate(raw_log_string)

# Inspect findings and root cause
print(f"Overall Severity: {report.overall_severity.value}")
print(f"Primary Root Cause: {report.root_cause.primary_cause}")
print(f"Confidence: {report.root_cause.confidence * 100:.1f}%")

print("\nCausal Chain:")
for step in report.root_cause.causal_chain:
    print(f"  {step}")

print(f"\nExtracted Evidence ({len(report.evidence)} items):")
for item in report.evidence:
    print(f"  [Line {item.line_number}] [{item.category}] {item.description}")
    print(f"    Raw log: {item.raw_log.strip()}")

# Export as Markdown or JSON
markdown_report = report.to_markdown()
json_report = report.to_json()
```

---

## 🤖 Optional LLM Augmentation (Gemini)

If you have a `GEMINI_API_KEY`, the agent can optionally perform AI-augmented reasoning on top of the gathered evidence:

```bash
export GEMINI_API_KEY="your-api-key"
python3 main.py sample_logs/oom_killed.log --llm
```

---

## 🧪 Running Unit Tests

Run the full test suite using Python's standard `unittest`:

```bash
python3 -m unittest discover tests -v
```
