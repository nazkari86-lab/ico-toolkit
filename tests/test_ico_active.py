from __future__ import annotations

import http.server
import os
import stat
import tempfile
import threading
import unittest
from pathlib import Path

from ico_active import AuthorizedClient, TargetPolicy, discover_service_urls, run_active_task
from ico_scan import run_scan
from ico_scan_core import CommandRunner, RunnerPolicy


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - stdlib callback name
        body = b"ico{active_route_fixture}" if self.path == "/hidden" else b"local fixture"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802 - stdlib callback name
        body = b"ico{active_http_fixture}"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


class ActiveClientTests(unittest.TestCase):
    def test_discovers_task_urls_and_captures_http_and_local_binary_flags(self):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                executable = root / "runner"
                executable.write_text("#!/bin/sh\nprintf 'ico{active_binary_fixture}\\n'\n", encoding="utf-8")
                executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
                url = f"http://127.0.0.1:{server.server_port}/"
                request = root / "request.sh"
                request.write_text(f"app.get('/hidden', handler)\ncurl -X POST -d 'probe=1' {url}\n", encoding="utf-8")
                result = run_active_task(
                    task_text="Replay the supplied service request.",
                    task_paths=(executable, request),
                    task_root=root,
                    runner=CommandRunner(root / "logs", policy=RunnerPolicy(max_cpu_seconds=2, max_memory_bytes=64 * 1024 * 1024)),
                    timeout_seconds=2,
                )
            self.assertEqual(discover_service_urls(f"See {url}."), (url,))
            self.assertEqual(len(result.requests), 3)
            self.assertEqual(len(result.executions), 1)
            self.assertIn("ico{active_binary_fixture}", {item["value"] for item in result.candidates})
            self.assertIn("ico{active_http_fixture}", {item["value"] for item in result.candidates})
            self.assertIn("ico{active_route_fixture}", {item["value"] for item in result.candidates})
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

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
