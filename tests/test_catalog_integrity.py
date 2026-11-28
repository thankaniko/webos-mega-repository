"""Offline regression tests for catalog identity and conflict quarantine."""
import unittest
from unittest.mock import patch
from scripts.audit import conflicting_versions, validate_baseline, scan_source, candidate

A = "a" * 64
B = "b" * 64

def pkg(ident="org.example.app", sha=A, ver="1.0.0"):
    return {"id": ident, "manifest": {"id": ident, "version": ver,
                                      "ipkHash": {"sha256": sha}}}

class CatalogIntegrity(unittest.TestCase):
    def test_valid_distinct_packages(self):
        validate_baseline([pkg(), pkg("org.example.other", B)])

    def test_duplicate_id(self):
        with self.assertRaisesRegex(ValueError, "baseline ID"):
            validate_baseline([pkg(), pkg(sha=B)])

    def test_divergent_id(self):
        p = pkg()
        p["manifest"]["id"] = "org.example.other"
        with self.assertRaisesRegex(ValueError, "baseline ID"):
            validate_baseline([p])

    def test_duplicate_digest(self):
        with self.assertRaisesRegex(ValueError, "baseline SHA-256"):
            validate_baseline([pkg(), pkg("org.example.other")])

    def test_invalid_version(self):
        with self.assertRaisesRegex(ValueError, "version"):
            validate_baseline([pkg(ver="1.0.0-beta")])

    def test_conflict(self):
        self.assertEqual(conflicting_versions({("1.0.0", B): {}, ("1.0.0", A): {}}),
                         {"1.0.0": [A, B]})

    def test_different_versions_not_conflict(self):
        self.assertEqual(conflicting_versions({("1.0.0", A): {}, ("1.1.0", B): {}}), {})

class DeprecatedPackages(unittest.TestCase):
    def test_legacy_chromium_excluded(self):
        p = pkg("org.nativechromium.browser")
        p["title"] = "Chromium (old)"
        p["manifest"].update(rootRequired=False, ipkUrl="https://github.com/example/repo/releases/download/v1.0.0/old.ipk")
        with self.assertRaisesRegex(ValueError, "restricted"):
            candidate(p, "https://raw.githubusercontent.com/example/repo/main/apps.json")

class FeedIsolation(unittest.TestCase):
    URL = "https://repo.webosbrew.org/apps.json"

    def test_non_object_isolated(self):
        with patch("scripts.audit.read_json", return_value=({"packages": [None, {"id": "ok"}, 3]}, self.URL)), \
             patch("scripts.audit.candidate", return_value={"id": "ok"}):
            rows, errors = scan_source(self.URL)
        self.assertEqual(rows, [{"id": "ok"}])
        self.assertEqual(len(errors), 2)

    def test_non_object_page(self):
        with patch("scripts.audit.read_json", return_value=([], self.URL)):
            rows, errors = scan_source(self.URL)
        self.assertEqual(rows, [])
        self.assertIn("packages array", errors[0]["reason"])

    def test_oversized_page(self):
        with patch("scripts.audit.read_json", return_value=({"packages": [{}] * 1001}, self.URL)):
            rows, errors = scan_source(self.URL)
        self.assertEqual(rows, [])
        self.assertIn("1000", errors[0]["reason"])

    def test_cycle_discards_partial_results(self):
        page = {"packages": [{}], "paging": {"nextUrl": self.URL}}
        with patch("scripts.audit.read_json", return_value=(page, self.URL)), \
             patch("scripts.audit.absolute", return_value=self.URL), \
             patch("scripts.audit.candidate", return_value={"id": "ok"}):
            rows, errors = scan_source(self.URL)
        self.assertEqual(rows, [])
        self.assertEqual(errors[-1]["discarded_candidates"], 1)

    def test_page_limit_discards_partial_results(self):
        def page(url):
            return {"packages": [{}], "paging": {"nextUrl": url + "x"}}, url
        with patch("scripts.audit.read_json", side_effect=page), \
             patch("scripts.audit.absolute", side_effect=lambda base, url: url), \
             patch("scripts.audit.candidate", return_value={"id": "ok"}):
            rows, errors = scan_source(self.URL)
        self.assertEqual(rows, [])
        self.assertEqual(errors[-1]["discarded_candidates"], 20)

    def test_invalid_paging_discards_partial(self):
        with patch("scripts.audit.read_json", return_value=({"packages": [{}], "paging": "bad"}, self.URL)), \
             patch("scripts.audit.candidate", return_value={"id": "ok"}):
            rows, errors = scan_source(self.URL)
        self.assertEqual(rows, [])
        self.assertIn("paging", errors[-1]["reason"])

if __name__ == "__main__":
    unittest.main()
