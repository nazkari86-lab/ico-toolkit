from __future__ import annotations

import base64
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ico_quals_active import main, solve_backdoor_instance


class _BackdoorHandler(BaseHTTPRequestHandler):
    route_paths = ("/wp2shell/v1/f8b000a326e88105cb84a05c",)
    request_methods: list[str] = []
    post_requests: list[tuple[str, dict[str, object]]] = []
    response_body = b'{"output":"ico{first_flag}\\nUSER_FLAG=ico{second_flag}\\n"}'

    def do_GET(self):  # noqa: N802 - stdlib callback name
        self.request_methods.append("GET")
        if self.path != "/wp-json/":
            self.send_error(404)
            return
        routes = {
            path: {
                "namespace": "wp2shell/v1",
                "methods": ["POST"],
                "endpoints": [{"methods": ["POST"], "args": {"c": {"type": "string"}}}],
            }
            for path in self.route_paths
        }
        body = json.dumps({"namespaces": ["wp2shell/v1"], "routes": routes}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802 - stdlib callback name
        self.request_methods.append("POST")
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length))
        self.post_requests.append((self.path, request))
        body = self.response_body
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


class BackdoorActiveSolverTests(unittest.TestCase):
    def setUp(self):
        _BackdoorHandler.route_paths = ("/wp2shell/v1/f8b000a326e88105cb84a05c",)
        _BackdoorHandler.request_methods = []
        _BackdoorHandler.post_requests = []
        _BackdoorHandler.response_body = b'{"output":"ico{first_flag}\\nUSER_FLAG=ico{second_flag}\\n"}'

    def _start_server(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _BackdoorHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def stop_server():
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.addCleanup(stop_server)
        target = f"http://127.0.0.1:{server.server_port}"
        return server, target

    def test_discovers_route_then_reads_both_task_flags_in_one_authorized_request(self):
        _server, target = self._start_server()
        with tempfile.TemporaryDirectory() as temp:
            result = solve_backdoor_instance(
                target,
                authorized_targets=(target,),
                allow_network=True,
                output_dir=Path(temp),
            )
            transcript = Path(result.artifacts[0]).read_text(encoding="utf-8")

        self.assertEqual(result.task_id, "backdoor")
        self.assertEqual(result.status, "candidate")
        self.assertEqual(_BackdoorHandler.request_methods, ["GET", "POST"])
        self.assertEqual(
            [candidate["value"] for candidate in result.candidates],
            ["ico{first_flag}", "ico{second_flag}"],
        )
        self.assertTrue(all(candidate["state"] == "transcript-derived" for candidate in result.candidates))
        self.assertEqual(len(_BackdoorHandler.post_requests), 1)
        request_path, request_body = _BackdoorHandler.post_requests[0]
        self.assertEqual(request_path, "/wp-json/wp2shell/v1/f8b000a326e88105cb84a05c")
        command = base64.b64decode(str(request_body["c"])).decode()
        self.assertIn("cat /flag.txt", command)
        self.assertIn("/proc/self/environ", command)
        self.assertIn('"status": 200', transcript)

    def test_refuses_platform_and_mismatched_origin_before_any_request(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(PermissionError):
                solve_backdoor_instance(
                    "https://cyberolympiad.kz",
                    authorized_targets=("https://cyberolympiad.kz",),
                    allow_network=True,
                    output_dir=Path(temp),
                )
            with self.assertRaises(PermissionError):
                solve_backdoor_instance(
                    "http://127.0.0.1:8001",
                    authorized_targets=("http://127.0.0.1:8002",),
                    allow_network=True,
                    output_dir=Path(temp),
                )

    def test_requires_explicit_network_opt_in(self):
        _server, target = self._start_server()
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(PermissionError):
                solve_backdoor_instance(
                    target,
                    authorized_targets=(target,),
                    allow_network=False,
                    output_dir=Path(temp),
                )
        self.assertEqual(_BackdoorHandler.request_methods, [])

    def test_ambiguous_rest_routes_are_reviewed_without_posting(self):
        _BackdoorHandler.route_paths = (
            "/wp2shell/v1/first-route",
            "/wp2shell/v1/second-route",
        )
        _server, target = self._start_server()
        with tempfile.TemporaryDirectory() as temp:
            result = solve_backdoor_instance(
                target,
                authorized_targets=(target,),
                allow_network=True,
                output_dir=Path(temp),
            )
        self.assertEqual(result.status, "candidate-review")
        self.assertEqual(_BackdoorHandler.request_methods, ["GET"])
        self.assertEqual(_BackdoorHandler.post_requests, [])
        self.assertIn("route", result.steps[-1]["name"])

    def test_cli_writes_a_machine_readable_report_for_the_explicit_target(self):
        _server, target = self._start_server()
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "report"
            status = main(
                [
                    "--allow-network",
                    "--authorized-target",
                    target,
                    "--target",
                    target,
                    "--out",
                    str(output),
                ]
            )
            report = json.loads((output / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(status, 0)
        self.assertEqual([item["value"] for item in report["candidates"]], ["ico{first_flag}", "ico{second_flag}"])


if __name__ == "__main__":
    unittest.main()
