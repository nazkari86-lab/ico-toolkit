#!/usr/bin/env python3
"""Explicit allowlisted HTTP client for local/authorized task hosts.

The ordinary ``ico-scan`` path never imports or calls this client.  Callers
must construct a policy themselves, which makes the network boundary visible
in code and in the resulting request records.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import socket
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping
from urllib.parse import urljoin, urlsplit

from ico_scan_core import CommandRunner, FlagMatcher


_SERVICE_URL = re.compile(r"https?://[^\s<>'\"`\\]+", re.IGNORECASE)
_SOURCE_ROUTE = re.compile(r"(?:\.route|\.(?:get|post|put|patch|delete)|router\.(?:get|post|put|patch|delete))\s*\(\s*[\"'](/[^\"'<>\s{}]*)", re.IGNORECASE)
_RUNNABLE_SUFFIXES = {"", ".bin", ".elf", ".exe", ".out"}
_NON_EXECUTABLE_SUFFIXES = {".so", ".dylib", ".a", ".o", ".py", ".pyc", ".js", ".wasm"}


@dataclass(frozen=True)
class TargetPolicy:
    allowed_hosts: tuple[str, ...] = ()
    blocked_hosts: tuple[str, ...] = ("cyberolympiad.kz",)
    max_requests: int = 10
    timeout_seconds: float = 10.0
    max_response_bytes: int = 4 * 1024 * 1024

    def __post_init__(self) -> None:
        if self.max_requests < 1 or self.timeout_seconds <= 0 or self.max_response_bytes < 1:
            raise ValueError("active policy limits must be positive")


@dataclass
class ResponseRecord:
    method: str
    url: str
    status: int | None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "headers": self.headers,
            "body_bytes": len(self.body),
            "body": self.body.decode("utf-8", errors="replace"),
            "error": self.error,
        }


@dataclass
class ActiveTaskResult:
    """Captured evidence from an opt-in live task pass."""

    endpoints: list[str] = field(default_factory=list)
    requests: list[dict[str, object]] = field(default_factory=list)
    executions: list[dict[str, object]] = field(default_factory=list)
    candidates: list[dict[str, object]] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "endpoints": self.endpoints,
            "requests": self.requests,
            "executions": self.executions,
            "candidates": self.candidates,
        }


def discover_service_urls(task_text: str, explicit_urls: tuple[str, ...] = ()) -> tuple[str, ...]:
    """Return task-service URLs found in a statement or supplied explicitly."""

    urls: list[str] = []
    for raw in [*explicit_urls, *_SERVICE_URL.findall(task_text)]:
        value = raw.rstrip(".,;:!?)\\]}\"")
        parsed = urlsplit(value)
        if parsed.scheme in {"http", "https"} and parsed.hostname and value not in urls:
            urls.append(value)
    return tuple(urls)


def _flag_hits(matcher: FlagMatcher, payload: bytes, *, source: str, analyzer: str, **extra: object) -> list[dict[str, object]]:
    hits = matcher.scan(payload.decode("utf-8", errors="replace"), source=source, analyzer=analyzer)
    for hit in hits:
        hit.update({"state": "transcript-derived", "verification": "active-captured-output", **extra})
    return hits


def _runnable_paths(paths: tuple[Path, ...]) -> tuple[Path, ...]:
    selected: list[Path] = []
    for path in paths:
        try:
            resolved = path.resolve()
            if not resolved.is_file() or resolved.suffix.lower() in _NON_EXECUTABLE_SUFFIXES:
                continue
            if resolved.suffix.lower() not in _RUNNABLE_SUFFIXES or not os.access(resolved, os.X_OK):
                continue
        except OSError:
            continue
        selected.append(resolved)
    return tuple(selected[:4])


def _source_request_templates(paths: tuple[Path, ...], *, max_bytes: int = 256 * 1024) -> list[dict[str, object]]:
    """Read cURL/HAR/raw-HTTP requests already supplied with a task."""

    from ico_solver_engine import SolverLimits
    from ico_universal_web import parse_http_transcript

    templates: list[dict[str, object]] = []
    for path in paths:
        try:
            if not path.is_file() or path.stat().st_size > max_bytes:
                continue
            records = parse_http_transcript(path, SolverLimits(max_bytes=max_bytes, max_files=16, timeout_seconds=2))
        except (OSError, ValueError, UnicodeError):
            continue
        for record in records:
            url = str(record.get("url", ""))
            if urlsplit(url).scheme not in {"http", "https"}:
                continue
            templates.append(
                {
                    "method": str(record.get("method", "GET")).upper(),
                    "url": url,
                    "headers": record.get("request_headers", {}),
                    "body": record.get("request_body", ""),
                    "source": str(path),
                }
            )
    return templates[:32]


def _source_route_paths(text: str) -> tuple[str, ...]:
    """Extract literal web routes from supplied application source."""

    return tuple(dict.fromkeys(match.group(1) for match in _SOURCE_ROUTE.finditer(text)))[:32]


def run_active_task(
    *,
    task_text: str,
    task_paths: tuple[Path, ...],
    task_root: Path,
    runner: CommandRunner,
    explicit_urls: tuple[str, ...] = (),
    request_budget: int = 12,
    timeout_seconds: float = 8.0,
) -> ActiveTaskResult:
    """Probe discovered task services and execute provided binaries on demand.

    The caller opts in through ``ico-solve --active``. HTTP targets are only
    URLs from the task statement or explicit CLI values. On macOS local native
    binaries run under a temporary sandbox profile that denies their network
    access; network interaction belongs to the recorded HTTP client instead.
    """

    if request_budget < 1 or timeout_seconds <= 0:
        raise ValueError("active request budget and timeout must be positive")
    result = ActiveTaskResult()
    source_texts = [task_text]
    for path in task_paths:
        try:
            if path.is_file() and path.stat().st_size <= 256 * 1024:
                source_texts.append(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    endpoints = discover_service_urls("\n".join(source_texts), explicit_urls)
    result.endpoints.extend(endpoints)
    matcher = FlagMatcher()
    hosts = tuple(dict.fromkeys(urlsplit(url).hostname.lower() for url in endpoints if urlsplit(url).hostname))
    if hosts:
        client = AuthorizedClient(
            TargetPolicy(
                allowed_hosts=hosts,
                blocked_hosts=(),
                max_requests=request_budget,
                timeout_seconds=timeout_seconds,
            )
        )
        replayed: set[tuple[str, str, str]] = set()
        for url in endpoints:
            response = client.request("GET", url)
            record = response.to_dict()
            record["origin"] = "discovered-url"
            result.requests.append(record)
            result.candidates.extend(
                _flag_hits(
                    matcher,
                    response.body,
                    source=url,
                    analyzer="active-http-get",
                    http_status=response.status,
                )
            )
            replayed.add(("GET", url, ""))
        for path in _source_route_paths("\n".join(source_texts)):
            if client.request_count >= request_budget:
                break
            for endpoint in endpoints:
                url = urljoin(endpoint, path)
                key = ("GET", url, "")
                if key in replayed:
                    continue
                response = client.request("GET", url)
                record = response.to_dict()
                record["origin"] = "source-route-discovery"
                record["route"] = path
                result.requests.append(record)
                replayed.add(key)
                result.candidates.extend(
                    _flag_hits(
                        matcher,
                        response.body,
                        source=url,
                        analyzer="active-source-route",
                        http_status=response.status,
                        route=path,
                    )
                )
                if client.request_count >= request_budget:
                    break
        for template in _source_request_templates(task_paths):
            if client.request_count >= request_budget:
                break
            method = str(template["method"])
            url = str(template["url"])
            body = str(template["body"])
            key = (method, url, body)
            if key in replayed or (urlsplit(url).hostname or "").lower() not in hosts:
                continue
            raw_headers = template["headers"]
            headers = {str(key): str(value) for key, value in raw_headers.items()} if isinstance(raw_headers, Mapping) else {}
            response = client.request(method, url, headers=headers, body=body)
            record = response.to_dict()
            record["origin"] = "source-request-template"
            record["template_source"] = str(template["source"])
            result.requests.append(record)
            replayed.add(key)
            result.candidates.extend(
                _flag_hits(
                    matcher,
                    response.body,
                    source=url,
                    analyzer="active-source-request",
                    http_status=response.status,
                    template_source=str(template["source"]),
                )
            )
    for index, executable in enumerate(_runnable_paths(task_paths)):
        args = [str(executable)]
        sandboxed = False
        if sys.platform == "darwin" and Path("/usr/bin/sandbox-exec").is_file():
            args = ["/usr/bin/sandbox-exec", "-p", "(version 1) (deny network*) (allow default)", str(executable)]
            sandboxed = True
        command = runner.run(
            args,
            cwd=task_root,
            timeout=timeout_seconds,
            log_name=f"active-local-{index:02d}",
        )
        combined = command.combined_output().encode("utf-8", errors="replace")
        result.executions.append(
            {
                "path": str(executable),
                "args": command.args,
                "returncode": command.returncode,
                "timed_out": command.timed_out,
                "duration_seconds": command.duration_seconds,
                "log_path": command.log_path,
                "sandboxed": sandboxed,
            }
        )
        result.candidates.extend(
            _flag_hits(
                matcher,
                combined,
                source=str(executable),
                analyzer="active-local-execution",
                sandboxed=sandboxed,
                returncode=command.returncode,
            )
        )
    return result


def _host_allowed(host: str, policy: TargetPolicy) -> bool:
    host = host.rstrip(".").lower()
    blocked = {item.rstrip(".").lower() for item in policy.blocked_hosts}
    if any(host == item or host.endswith("." + item) for item in blocked):
        return False
    allowed = {item.rstrip(".").lower() for item in policy.allowed_hosts}
    return host in allowed


class AuthorizedClient:
    def __init__(self, policy: TargetPolicy) -> None:
        self.policy = policy
        self.request_count = 0

    def request(self, method: str, url: str, **kwargs: object) -> ResponseRecord:
        method = method.upper()
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("active client requires an http(s) URL")
        if not _host_allowed(parsed.hostname, self.policy):
            raise PermissionError(f"host is not allowlisted: {parsed.hostname}")
        if self.request_count >= self.policy.max_requests:
            raise PermissionError("active request budget exhausted")
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            raise ValueError(f"unsupported HTTP method: {method}")
        self.request_count += 1
        timeout = float(kwargs.get("timeout", self.policy.timeout_seconds))
        headers_value = kwargs.get("headers", {})
        headers = {str(key): str(value) for key, value in headers_value.items()} if isinstance(headers_value, Mapping) else {}
        body_value = kwargs.get("body", kwargs.get("data", b""))
        if isinstance(body_value, str):
            body = body_value.encode("utf-8")
        elif isinstance(body_value, bytes):
            body = body_value
        elif body_value is None:
            body = b""
        else:
            body = json.dumps(body_value).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        connection: http.client.HTTPConnection | http.client.HTTPSConnection
        connection = http.client.HTTPSConnection(parsed.hostname, port, timeout=timeout) if parsed.scheme == "https" else http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)
        record = ResponseRecord(method, url, None)
        try:
            connection.request(method, path, body=body or None, headers=headers)
            response = connection.getresponse()
            record.status = response.status
            record.headers = {key.lower(): value for key, value in response.getheaders()}
            record.body = response.read(self.policy.max_response_bytes + 1)[: self.policy.max_response_bytes]
        except (OSError, socket.timeout) as exc:
            record.error = f"{type(exc).__name__}: {exc}"
        finally:
            connection.close()
        return record
