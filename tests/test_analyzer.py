import contextlib
import io
import socket
import unittest
from unittest.mock import Mock, patch

import analyzer as app


class ValidationTests(unittest.TestCase):
    def test_valid_url(self):
        self.assertEqual(app.validate_url("https://example.com#section"),
                         ("https://example.com/", "example.com", 443))

    def test_invalid_urls(self):
        for url in ("", "example.com", "ftp://example.com", "https://user:pass@example.com",
                    "https://example.com:99999", "https://example.com:0", "https://example.com:8080", "https://example.com/\r\nX: y",
                    "http://[::1", "https://example.com\\@localhost", "http://[fe80::1%25en0]/"):
            with self.subTest(url=url), self.assertRaises(app.AnalyzerError):
                app.validate_url(url)

    def test_non_public_addresses(self):
        for address in ("127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254",
                        "0.0.0.0", "224.0.0.1", "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1"):
            with self.subTest(address=address):
                self.assertFalse(app.public_ip(address))
        self.assertTrue(app.public_ip("8.8.8.8"))

    @patch("analyzer.socket.getaddrinfo")
    def test_mixed_dns_blocked(self, dns):
        dns.return_value = [(2, 1, 6, "", (ip, 443)) for ip in ("8.8.8.8", "127.0.0.1")]
        with self.assertRaises(app.AnalyzerError):
            app.resolve_public("example.com", 443)

    @patch("analyzer.socket.getaddrinfo", side_effect=socket.gaierror())
    def test_dns_failure(self, dns):
        with self.assertRaises(app.AnalyzerError):
            app.resolve_public("example.com", 443)

    @patch("analyzer.queue.Queue")
    def test_dns_timeout(self, queue):
        queue.return_value.get.side_effect = app.queue.Empty
        with self.assertRaises(app.AnalyzerError):
            app.resolve_public("example.com", 443, 0.01)


class FetchTests(unittest.TestCase):
    def setUp(self):
        resolver = patch("analyzer.resolve_public", return_value=["8.8.8.8"])
        self.resolve = resolver.start()
        self.addCleanup(resolver.stop)
        requester = patch("analyzer.request_headers", return_value=(200, []))
        self.request = requester.start()
        self.addCleanup(requester.stop)

    def test_relative_redirect_and_final_headers(self):
        self.request.side_effect = [(302, [("Location", "/next")]), (200, [("X-Content-Type-Options", "nosniff")])]
        url, status, headers = app.fetch_headers("https://example.com")
        self.assertEqual(url, "https://example.com/next")
        self.assertEqual(headers["x-content-type-options"], ["nosniff"])
        self.assertEqual(self.resolve.call_count, 2)
        self.assertEqual(status, 200)

    def test_redirect_internal_blocked_before_request(self):
        self.request.return_value = (302, [("Location", "http://127.0.0.1/")])
        self.resolve.side_effect = [["8.8.8.8"], app.AnalyzerError("Destino bloqueado")]
        with self.assertRaises(app.AnalyzerError):
            app.fetch_headers("http://example.com")
        self.assertEqual(self.request.call_count, 1)

    def test_https_downgrade(self):
        self.request.return_value = (302, [("Location", "http://example.com/")])
        with self.assertRaises(app.AnalyzerError):
            app.fetch_headers("https://example.com")
        self.assertEqual(self.request.call_count, 1)

    def test_loop(self):
        self.request.return_value = (302, [("Location", "/")])
        with self.assertRaises(app.AnalyzerError):
            app.fetch_headers("https://example.com")

    def test_redirect_limit(self):
        self.request.side_effect = [(302, [("Location", f"/{i}")]) for i in range(7)]
        with self.assertRaises(app.AnalyzerError):
            app.fetch_headers("https://example.com")
        self.assertEqual(self.request.call_count, 6)

    def test_bad_location(self):
        for pairs in ([], [("Location", "a"), ("Location", "b")], [("Location", "file:///etc/passwd")], [("Location", "\n/next")]):
            self.request.return_value = (302, pairs)
            with self.subTest(pairs=pairs), self.assertRaises(app.AnalyzerError):
                app.fetch_headers("https://example.com")

    def test_connection_timeout(self):
        self.request.side_effect = socket.timeout("timeout")
        with self.assertRaises(app.AnalyzerError):
            app.fetch_headers("https://example.com")


class ConnectionTests(unittest.TestCase):
    @patch("analyzer.ssl.create_default_context")
    @patch("analyzer.socket.create_connection")
    def test_pinned_ip_and_tls_hostname(self, connect, context):
        connection = app.PinnedConnection("example.com", 443, "8.8.8.8", True, 5)
        connection.connect()
        connect.assert_called_once_with(("8.8.8.8", 443), 5)
        context.return_value.wrap_socket.assert_called_once_with(connect.return_value, server_hostname="example.com")

    @patch("analyzer.PinnedConnection")
    def test_no_body_read_and_connection_closed(self, connection):
        response = connection.return_value.getresponse.return_value
        response.status = 200
        response.getheaders.return_value = []
        self.assertEqual(app.request_headers("https://example.com/", "example.com", 443, "8.8.8.8", 5), (200, []))
        response.read.assert_not_called()
        connection.return_value.close.assert_called_once()


class AnalysisTests(unittest.TestCase):
    def test_missing_headers(self):
        findings, score = app.analyze_headers({})
        self.assertEqual(score, 0)
        self.assertTrue(all(item.state == "AUSENTE" for item in findings))

    def test_basic_good_headers(self):
        findings, score = app.analyze_headers({
            "content-security-policy": "default-src 'self'; object-src 'none'",
            "STRICT-TRANSPORT-SECURITY": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
        })
        self.assertEqual(score, 100)
        self.assertTrue(all(item.state == "PRESENTE" for item in findings))

    def test_review_values(self):
        values = ("default-src *", "max-age=0", "invalid", "unsafe-url")
        findings, score = app.analyze_headers(dict(zip(app.HEADERS, values)))
        self.assertEqual(score, 40)
        self.assertTrue(all(item.state == "REVISAR" for item in findings))

    def test_empty_duplicate_and_http_hsts(self):
        for value in ("", ["nosniff", "nosniff"]):
            findings, _ = app.analyze_headers({"X-Content-Type-Options": value})
            self.assertEqual(findings[2].state, "REVISAR")
        findings, _ = app.analyze_headers({"Strict-Transport-Security": "max-age=31536000"}, https=False)
        self.assertEqual(findings[1].state, "REVISAR")

    @patch("analyzer.fetch_headers", return_value=("https://example.com/", 200, {}))
    def test_cli_output(self, fetch):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(app.main(["https://example.com"]), 0)
        self.assertIn("0/100", output.getvalue())
        self.assertIn("No equivale a Mozilla Observatory", output.getvalue())

    @patch("analyzer.fetch_headers", side_effect=app.AnalyzerError("fallo"))
    def test_cli_error(self, fetch):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(app.main(["invalid"]), 1)

    def test_terminal_controls(self):
        self.assertEqual(app.safe_text("a\x1b\r\nb"), "a???b")

    def test_extremely_large_hsts_age(self):
        self.assertEqual(app.review_value("Strict-Transport-Security", "max-age=" + "9" * 5000, True), "")


if __name__ == "__main__":
    unittest.main()
