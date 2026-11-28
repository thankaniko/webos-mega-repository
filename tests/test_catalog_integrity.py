"""Offline regression tests for catalog identity and conflict quarantine."""
import unittest
from scripts.audit import conflicting_versions, validate_baseline

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

if __name__ == "__main__":
    unittest.main()
