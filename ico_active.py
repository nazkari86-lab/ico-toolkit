#!/usr/bin/env python3
"""Explicit allowlisted HTTP client for local/authorized task hosts.

The ordinary ``ico-scan`` path never imports or calls this client.  Callers
must construct a policy themselves, which makes the network boundary visible
in code and in the resulting request records.
"""

from __future__ import annotations

import http.client
import json
import socket
from dataclasses import dataclass, field
from typing import Mapping
from urllib.parse import urlsplit


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

