"""
Tests for LogParser.
"""

import unittest
from k8s_agent.parser import LogParser


class TestLogParser(unittest.TestCase):

    def test_parse_cri_line(self):
        line = '2026-10-04T17:40:01.102Z stdout F [checkout-service-7d6f54c86-8x2lq] [INFO] Starting checkout processing batch #4012...'
        entry = LogParser.parse_line(line, line_number=1)

        self.assertEqual(entry.line_number, 1)
        self.assertEqual(entry.timestamp, "2026-10-04T17:40:01.102Z")
        self.assertEqual(entry.stream, "stdout")
        self.assertEqual(entry.pod_name, "checkout-service-7d6f54c86-8x2lq")
        self.assertIn("Starting checkout", entry.message)

    def test_parse_json_line(self):
        line = '{"timestamp": "2026-10-04T13:00:00Z", "level": "ERROR", "pod": "auth-service-78f9cd588-4n5kl", "namespace": "prod", "message": "Database pool exhausted"}'
        entry = LogParser.parse_line(line, line_number=5)

        self.assertTrue(entry.is_json)
        self.assertEqual(entry.level, "ERROR")
        self.assertEqual(entry.pod_name, "auth-service-78f9cd588-4n5kl")
        self.assertEqual(entry.namespace, "prod")
        self.assertEqual(entry.message, "Database pool exhausted")

    def test_parse_klog_line(self):
        line = 'E1004 12:00:00.123456 1234 pod_workers.go:123] Readiness probe failed: connection refused'
        entry = LogParser.parse_line(line, line_number=10)

        self.assertEqual(entry.level, "ERROR")
        self.assertIn("Readiness probe failed", entry.message)


if __name__ == "__main__":
    unittest.main()
