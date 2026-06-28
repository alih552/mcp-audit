"""Zero-dependency tests for mcp-audit. Run:  python3 -m unittest discover -s tests -v"""
import unittest
from pathlib import Path

from mcp_audit.audit import audit_config, audit_server, extract_servers, find_secrets

EX = Path(__file__).resolve().parent.parent / "examples"


class TestExtract(unittest.TestCase):
    def test_mcpservers_shape(self):
        self.assertEqual(set(extract_servers({"mcpServers": {"a": {"command": "x"}}})), {"a"})

    def test_vscode_nested_shape(self):
        self.assertEqual(set(extract_servers({"mcp": {"servers": {"b": {"url": "https://x"}}}})), {"b"})

    def test_bare_map_shape(self):
        self.assertEqual(set(extract_servers({"c": {"command": "x"}, "d": {"url": "https://y"}})), {"c", "d"})

    def test_empty(self):
        self.assertEqual(extract_servers({"unrelated": 1}), {})


class TestSecrets(unittest.TestCase):
    def test_github_token(self):
        hits = find_secrets('{"env": {"T": "ghp_AbCdEf0123456789AbCdEf0123456789AbCd"}}')
        self.assertTrue(any("GitHub" in label for label, _ in hits))

    def test_no_false_positive_on_clean(self):
        self.assertEqual(find_secrets('{"command": "npx", "args": ["server"]}'), [])


class TestAudit(unittest.TestCase):
    def test_insecure_scores_zero(self):
        res = audit_config(EX / "insecure.mcp.json")
        self.assertEqual(res.servers, 7)
        self.assertEqual(res.grade, "F")
        self.assertEqual(res.score, 0)
        ids = {f.id for f in res.findings}
        self.assertIn("remote-no-auth", ids)
        self.assertIn("cleartext-http", ids)
        self.assertIn("plaintext-secret", ids)
        self.assertIn("broad-filesystem", ids)
        self.assertTrue(res.counts()["HIGH"] >= 3)

    def test_good_is_clean(self):
        res = audit_config(EX / "good.mcp.json")
        self.assertEqual(res.score, 100)
        self.assertEqual(res.grade, "A")
        self.assertEqual(res.findings, [])

    def test_token_estimate_positive(self):
        res = audit_config(EX / "insecure.mcp.json")
        self.assertGreater(res.est_tokens, 0)

    def test_deprecated_sse(self):
        ids = {f.id for f in audit_server("x", {"type": "sse", "url": "https://x",
                                               "headers": {"Authorization": "Bearer y"}})}
        self.assertIn("deprecated-sse", ids)

    def test_credentials_in_url(self):
        ids = {f.id for f in audit_server("x", {"type": "http", "url": "https://user:pass@example.com"})}
        self.assertIn("credentials-in-url", ids)

    def test_inline_code_exec(self):
        ids = {f.id for f in audit_server("x", {"command": "python3", "args": ["-c", "print(1)"]})}
        self.assertIn("inline-code-exec", ids)

    def test_risk_class_grouping(self):
        from mcp_audit.audit import risk_class
        self.assertEqual(risk_class("remote-no-auth"), "Authentication")
        self.assertEqual(risk_class("plaintext-secret"), "Credentials & secrets")
        res = audit_config(EX / "insecure.mcp.json")
        classes = {c for c, _ in res.by_risk()}
        self.assertIn("Authentication", classes)
        self.assertIn("Code execution & supply chain", classes)


if __name__ == "__main__":
    unittest.main()
