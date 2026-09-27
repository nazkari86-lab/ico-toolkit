from __future__ import annotations

import http.server
import threading
import unittest
from pathlib import Path

from ico_active import AuthorizedClient, TargetPolicy
from ico_scan import run_scan


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - stdlib callback name
        body = b"local fixture"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


class ActiveClientTests(unittest.TestCase):
    def test_allowlisted_local_request_and_budget(self):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = AuthorizedClient(TargetPolicy(allowed_hosts=("127.0.0.1",), max_requests=1))
            response = client.request("GET", f"http://127.0.0.1:{server.server_port}/")
            self.assertEqual(response.status, 200)
            self.assertEqual(response.body, b"local fixture")
            with self.assertRaises(PermissionError):
                client.request("GET", f"http://127.0.0.1:{server.server_port}/again")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_blocked_and_unlisted_hosts_rejected_before_socket(self):
        client = AuthorizedClient(TargetPolicy(allowed_hosts=("localhost",)))
        with self.assertRaises(PermissionError):
            client.request("GET", "https://cyberolympiad.kz/")
        with self.assertRaises(PermissionError):
            client.request("GET", "http://example.invalid/")

    def test_scan_active_policy_never_allows_platform_host(self):
        with self.assertRaises(ValueError):
            run_scan([], out_dir=Path("/tmp/ico-active-policy-test"), allow_network=True, authorized_targets=("https://cyberolympiad.kz",), verbose=False)


if __name__ == "__main__":
    unittest.main()
