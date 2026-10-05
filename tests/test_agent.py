"""
End-to-end integration tests for KubernetesInvestigationAgent.
"""

from pathlib import Path
import unittest

from k8s_agent.agent import KubernetesInvestigationAgent
from k8s_agent.models import Severity


class TestKubernetesInvestigationAgent(unittest.TestCase):

    def setUp(self):
        self.agent = KubernetesInvestigationAgent()
        self.sample_dir = Path(__file__).resolve().parent.parent / "sample_logs"

    def test_investigate_oom_scenario(self):
        log_file = self.sample_dir / "oom_killed.log"
        report = self.agent.investigate_file(log_file)

        self.assertEqual(report.overall_severity, Severity.CRITICAL)
        self.assertEqual(report.target_workload, "checkout-service-7d6f54c86-8x2lq")
        self.assertEqual(report.namespace, "production")
        self.assertIsNotNone(report.root_cause)
        self.assertIn("OOM", report.root_cause.primary_cause)
        self.assertGreater(len(report.evidence), 0)
        self.assertGreater(len(report.remediations), 0)

        # Check evidence line numbers
        oom_ev = [e for e in report.evidence if e.category == "MEMORY_EXHAUSTION"]
        self.assertTrue(any(e.line_number == 7 for e in oom_ev))

    def test_investigate_probe_scenario(self):
        log_file = self.sample_dir / "crashloop_probe.log"
        report = self.agent.investigate_file(log_file)

        self.assertEqual(report.target_workload, "payment-gateway-69d5fb8bd6-m9z4p")
        self.assertEqual(report.namespace, "staging")
        self.assertIsNotNone(report.root_cause)
        self.assertIn("Probe", report.root_cause.primary_cause)

    def test_investigate_dns_scenario(self):
        log_file = self.sample_dir / "dns_network_failure.log"
        report = self.agent.investigate_file(log_file)

        self.assertEqual(report.overall_severity, Severity.HIGH)
        self.assertEqual(report.target_workload, "inventory-api-5c94f576b8-29hjt")
        self.assertIn("DNS", report.root_cause.primary_cause)

    def test_investigate_rbac_scenario(self):
        log_file = self.sample_dir / "rbac_permission_denied.log"
        report = self.agent.investigate_file(log_file)

        self.assertEqual(report.target_workload, "custom-operator-56c4d7b7db-k8m5w")
        self.assertIn("RBAC", report.root_cause.primary_cause)

    def test_investigate_raw_text(self):
        raw_log = """
        2026-10-04T12:00:00Z stdout F [my-app-pod-12345-abcde] Initializing server
        2026-10-04T12:00:02Z stderr F [my-app-pod-12345-abcde] panic: runtime error: index out of range [10] with length 2
        2026-10-04T12:00:05Z stderr F kubelet: Back-off restarting failed container my-app-pod
        """
        report = self.agent.investigate(raw_log)
        self.assertEqual(report.target_workload, "my-app-pod-12345-abcde")
        self.assertIn("Exception", report.root_cause.primary_cause)
        self.assertGreater(len(report.evidence), 0)

    def test_export_formats(self):
        log_file = self.sample_dir / "oom_killed.log"
        report = self.agent.investigate_file(log_file)

        md = report.to_markdown() if hasattr(report, "to_markdown") else self.agent.render_markdown(report)
        self.assertIn("# 🔍 Kubernetes Log Investigation Report", md)
        self.assertIn("## 🎯 Root Cause Analysis (RCA)", md)
        self.assertIn("## 📑 Supporting Evidence", md)

        js = report.to_json()
        self.assertIn('"overall_severity": "CRITICAL"', js)
        self.assertIn('"evidence"', js)


if __name__ == "__main__":
    unittest.main()
