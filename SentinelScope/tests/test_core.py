import unittest

from sentinelscope.core import analyze_lines


class AnalyzeLinesTests(unittest.TestCase):
    def test_finds_repeated_ssh_failures_and_ioc(self):
        lines = [f"Failed password for root from 203.0.113.8 port {5000 + i} ssh2" for i in range(5)]
        report = analyze_lines(lines, ["203.0.113.8"])
        self.assertEqual(report["summary"]["ssh_failed_logins"], 5)
        self.assertEqual(report["summary"]["ioc_hits"], 5)
        self.assertEqual(report["brute_force_sources"][0]["source_ip"], "203.0.113.8")

    def test_empty_input(self):
        report = analyze_lines([])
        self.assertEqual(report["summary"]["lines_analyzed"], 0)
        self.assertEqual(report["brute_force_sources"], [])

    def test_ignores_invalid_ip_in_ssh_line(self):
        report = analyze_lines(["Failed password for root from 999.999.999.999 port 22 ssh2"])
        self.assertEqual(report["summary"]["ssh_failed_logins"], 0)


if __name__ == "__main__":
    unittest.main()
