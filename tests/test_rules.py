"""
Tests for InvestigationRules and pattern matching.
"""

import unittest
from k8s_agent.models import Severity
from k8s_agent.rules import get_default_rules


class TestInvestigationRules(unittest.TestCase):

    def setUp(self):
        self.rules = {r.rule_id: r for r in get_default_rules()}

    def test_oom_rule(self):
        rule = self.rules["OOM_KILLED_EXIT_137"]
        self.assertEqual(rule.severity, Severity.CRITICAL)

        self.assertIsNotNone(rule.matches("container terminated with exit code 137 (OOMKilled)"))
        self.assertIsNotNone(rule.matches("kernel: Out of memory: Killed process 14210"))
        self.assertIsNotNone(rule.matches("java.lang.OutOfMemoryError: Java heap space"))
        self.assertIsNone(rule.matches("Started container checkout successfully"))

    def test_crashloop_rule(self):
        rule = self.rules["CRASH_LOOP_BACKOFF"]
        self.assertIsNotNone(rule.matches("CrashLoopBackOff: back-off 10s restarting failed container"))
        self.assertIsNotNone(rule.matches("Back-off restarting failed container"))

    def test_probe_rule(self):
        rule = self.rules["READINESS_PROBE_FAILED"]
        self.assertIsNotNone(rule.matches('Readiness probe failed: Get "http://localhost:8080/health": connection refused'))

    def test_network_exclusion_for_probe(self):
        net_rule = self.rules["NETWORK_CONNECTION_REFUSED"]
        # Should NOT match when probe failed is in text
        self.assertIsNone(net_rule.matches('Readiness probe failed: connect: connection refused'))
        # Should match real inter-service network error
        self.assertIsNotNone(net_rule.matches('connect: connection refused to mysql-primary:3306'))


if __name__ == "__main__":
    unittest.main()
