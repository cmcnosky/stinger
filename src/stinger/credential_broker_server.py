"""Minimal fixed-origin credential-injecting reverse proxy for Protocol 2.

This file is mounted read-only into a trusted broker sidecar.  The untrusted agent is on a
different, Docker-internal network and receives only an opaque lease.  The raw provider
credential exists only in this process and is injected after the request has matched one
exact signed route.  This is intentionally not a general HTTP proxy.

The module uses only the Python standard library so the already-approved Stinger runner
image can execute its exact source bytes without installing another dependency.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import signal
import ssl
import sys
import threading
from base64 import b64encode, urlsafe_b64encode
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar, cast
from urllib.parse import quote_from_bytes, urlsplit

MAX_REQUEST_BYTES = 16 * 1024 * 1024
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
EXPECTED_CONFIG_KEYS = frozenset(
    {
        "format_version",
        "configuration_sha256",
        "provider",
        "agent_base_url",
        "upstream_https_origin",
        "path_mappings",
        "forwarded_agent_headers",
        "stripped_agent_headers",
        "injected_auth_header",
        "injected_auth_scheme",
        "lease_sha256",
        "test_only_allow_http",
    }
)
HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)
PRODUCTION_ROUTE_CONFIGS: dict[str, dict[str, object]] = {
    "openai": {
        "agent_base_url": "http://stinger-credential-broker:8765/openai/v1",
        "upstream_https_origin": "https://api.openai.com:443",
        "path_mappings": [
            {
                "agent_path": "/openai/v1/responses",
                "upstream_path": "/v1/responses",
                "methods": ["POST"],
            },
            {
                "agent_path": "/openai/v1/responses/compact",
                "upstream_path": "/v1/responses/compact",
                "methods": ["POST"],
            },
        ],
        "forwarded_agent_headers": [
            "accept",
            "content-type",
            "openai-beta",
            "user-agent",
        ],
        "stripped_agent_headers": [
            "authorization",
            "cookie",
            "host",
            "proxy-authorization",
            "x-api-key",
        ],
        "injected_auth_header": "authorization",
        "injected_auth_scheme": "bearer",
    },
    "anthropic": {
        "agent_base_url": "http://stinger-credential-broker:8765/anthropic",
        "upstream_https_origin": "https://api.anthropic.com:443",
        "path_mappings": [
            {
                "agent_path": "/anthropic/v1/messages",
                "upstream_path": "/v1/messages",
                "methods": ["POST"],
            },
            {
                "agent_path": "/anthropic/v1/messages/count_tokens",
                "upstream_path": "/v1/messages/count_tokens",
                "methods": ["POST"],
            },
        ],
        "forwarded_agent_headers": [
            "accept",
            "anthropic-beta",
            "anthropic-version",
            "content-type",
            "user-agent",
        ],
        "stripped_agent_headers": [
            "authorization",
            "cookie",
            "host",
            "proxy-authorization",
            "x-api-key",
        ],
        "injected_auth_header": "x-api-key",
        "injected_auth_scheme": "raw",
    },
}


class BrokerConfigurationError(Exception):
    """Raised before listening when the exact broker configuration is invalid."""


class CredentialBrokerHTTPServer(ThreadingHTTPServer):
    """Threaded server whose close waits for every credentialed request to terminate."""

    daemon_threads = False
    block_on_close = True


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _load_configuration(path: Path) -> dict[str, Any]:
    """Load one closed, non-secret broker configuration."""
    try:
        raw_bytes = path.read_bytes()
        raw = json.loads(raw_bytes)
    except (OSError, json.JSONDecodeError) as exc:
        raise BrokerConfigurationError("broker configuration is unreadable") from exc
    if not isinstance(raw, dict) or set(raw) != EXPECTED_CONFIG_KEYS:
        raise BrokerConfigurationError("broker configuration schema is not exact")
    if raw_bytes != _canonical_bytes(raw):
        raise BrokerConfigurationError("broker configuration is not canonical JSON")
    if raw["format_version"] != "1":
        raise BrokerConfigurationError("broker configuration format is unsupported")
    if not isinstance(raw["test_only_allow_http"], bool):
        raise BrokerConfigurationError("broker test-only mode must be boolean")
    for name in ("configuration_sha256", "lease_sha256"):
        value = raw[name]
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise BrokerConfigurationError(f"{name} is not a canonical SHA-256")
    _validate_origin(raw)
    _validate_routes(raw)
    _validate_headers(raw)
    _validate_closed_production_route(raw)
    return raw


def _validate_origin(config: dict[str, Any]) -> None:
    origin = config["upstream_https_origin"]
    if not isinstance(origin, str):
        raise BrokerConfigurationError("provider upstream origin is invalid")
    try:
        parsed = urlsplit(origin)
        port = parsed.port
    except ValueError as exc:
        raise BrokerConfigurationError("provider upstream origin is invalid") from exc
    test_only = config["test_only_allow_http"] is True
    if (
        parsed.scheme not in ({"https", "http"} if test_only else {"https"})
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or port is None
    ):
        raise BrokerConfigurationError("provider upstream must be one exact origin")


def _validate_routes(config: dict[str, Any]) -> None:
    mappings = config["path_mappings"]
    if not isinstance(mappings, list) or not mappings:
        raise BrokerConfigurationError("broker path mapping is empty")
    seen: set[str] = set()
    for mapping in mappings:
        if not isinstance(mapping, dict) or set(mapping) != {
            "agent_path",
            "upstream_path",
            "methods",
        }:
            raise BrokerConfigurationError("broker path mapping schema is not exact")
        agent_path = mapping["agent_path"]
        upstream_path = mapping["upstream_path"]
        methods = mapping["methods"]
        if (
            not isinstance(agent_path, str)
            or not isinstance(upstream_path, str)
            or not agent_path.startswith("/")
            or not upstream_path.startswith("/")
            or agent_path.startswith("//")
            or upstream_path.startswith("//")
            or any(
                token in agent_path or token in upstream_path for token in ("..", "\\", "?", "#")
            )
            or not isinstance(methods, list)
            or methods != ["POST"]
            or agent_path in seen
        ):
            raise BrokerConfigurationError("broker path mapping is not canonical")
        seen.add(agent_path)


def _validate_headers(config: dict[str, Any]) -> None:
    forwarded = config["forwarded_agent_headers"]
    stripped = config["stripped_agent_headers"]
    if (
        not isinstance(forwarded, list)
        or not isinstance(stripped, list)
        or any(not isinstance(item, str) or item != item.lower() for item in forwarded + stripped)
        or len(forwarded) != len(set(forwarded))
        or len(stripped) != len(set(stripped))
        or set(forwarded) & set(stripped)
        or not HOP_BY_HOP_HEADERS.isdisjoint(forwarded)
        or not {"authorization", "proxy-authorization", "x-api-key"}.issubset(stripped)
    ):
        raise BrokerConfigurationError("broker header policy is invalid")
    if config["injected_auth_header"] not in {"authorization", "x-api-key"}:
        raise BrokerConfigurationError("broker injection header is invalid")
    if config["injected_auth_scheme"] not in {"bearer", "raw"}:
        raise BrokerConfigurationError("broker injection scheme is invalid")


def _validate_closed_production_route(config: dict[str, Any]) -> None:
    """Reject any production destination/header/path mapping not compiled into this source."""
    if config["test_only_allow_http"] is True:
        return
    provider = config["provider"]
    if not isinstance(provider, str) or provider not in PRODUCTION_ROUTE_CONFIGS:
        raise BrokerConfigurationError("broker provider is not production-allowlisted")
    expected = PRODUCTION_ROUTE_CONFIGS[provider]
    if any(config[name] != value for name, value in expected.items()):
        raise BrokerConfigurationError("broker production route differs from the closed allowlist")


class CredentialBrokerHandler(BaseHTTPRequestHandler):
    """Handle only exact signed POST routes and inject broker-owned authorization."""

    protocol_version = "HTTP/1.1"
    config: ClassVar[dict[str, Any]]
    raw_credential: ClassVar[str]
    lease: ClassVar[str]
    audit_path: ClassVar[Path]
    audit_lock: ClassVar[threading.Lock]
    request_sequence: ClassVar[int]

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's public contract
        """Proxy one exact request or reject it without contacting any upstream."""
        request_id = self._next_request_id()
        try:
            route = self._authorize_request()
            body = self._request_body()
            self._audit(
                "attempt",
                reason="exact route authorized before upstream",
                request_id=request_id,
            )
            status, headers, response = self._upstream(route, body)
        except _RequestRejected as exc:
            self._audit("rejected", reason=exc.reason, request_id=request_id)
            self._reply(403, b'{"error":"credential broker request rejected"}\n')
            return
        except (OSError, http.client.HTTPException, ssl.SSLError):
            self._audit(
                "upstream-error",
                reason="fixed upstream request failed",
                request_id=request_id,
            )
            self._reply(502, b'{"error":"credential broker upstream failed"}\n')
            return
        except Exception:
            self._audit(
                "broker-error",
                reason="request handling failed closed",
                request_id=request_id,
            )
            self._reply(500, b'{"error":"credential broker failed closed"}\n')
            return
        if status < 200 or status >= 300:
            self._audit(
                "rejected",
                reason="upstream returned non-success",
                request_id=request_id,
            )
            self._reply(502, b'{"error":"credential broker upstream rejected"}\n')
            return
        serialized_headers = _canonical_bytes(headers)
        if self._contains_credential(response) or self._contains_credential(serialized_headers):
            self._audit(
                "rejected",
                reason="upstream reflected provider credential",
                request_id=request_id,
            )
            self._reply(502, b'{"error":"credential broker response rejected"}\n')
            return
        self._audit("allowed", reason="exact route completed", request_id=request_id)
        self.send_response(status)
        for name, value in headers:
            lowered = name.lower()
            if lowered in HOP_BY_HOP_HEADERS or lowered in {
                "authorization",
                "content-length",
                "proxy-authenticate",
                "set-cookie",
                "x-api-key",
            }:
                continue
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(response)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(response)
        self.close_connection = True

    def do_CONNECT(self) -> None:  # noqa: N802
        self._reject_method("CONNECT")

    def do_GET(self) -> None:  # noqa: N802
        self._reject_method("GET")

    def do_PUT(self) -> None:  # noqa: N802
        self._reject_method("PUT")

    def do_DELETE(self) -> None:  # noqa: N802
        self._reject_method("DELETE")

    def do_PATCH(self) -> None:  # noqa: N802
        self._reject_method("PATCH")

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._reject_method("OPTIONS")

    def do_HEAD(self) -> None:  # noqa: N802
        self._reject_method("HEAD")

    def do_TRACE(self) -> None:  # noqa: N802
        self._reject_method("TRACE")

    def send_error(
        self,
        code: int,
        message: str | None = None,
        explain: str | None = None,
    ) -> None:
        """Audit parser failures and arbitrary methods instead of emitting an unbound error."""
        self._audit(
            "rejected",
            reason="HTTP request parsing or method failed closed",
            request_id=self._next_request_id(),
        )
        status = 405 if code == 501 else 400
        self._reply(status, b'{"error":"credential broker request rejected"}\n')

    def _reject_method(self, method: str) -> None:
        self._audit(
            "rejected",
            reason="method is not approved",
            request_id=self._next_request_id(),
        )
        self._reply(405, b'{"error":"credential broker method rejected"}\n')

    def _authorize_request(self) -> dict[str, Any]:
        target = self.path
        if (
            not target.startswith("/")
            or target.startswith("//")
            or "?" in target
            or "#" in target
            or "\\" in target
            or ".." in target
            or urlsplit(target).scheme
            or urlsplit(target).netloc
        ):
            raise _RequestRejected("request target is not an exact origin-form path")
        if any(len(self.headers.get_all(name, [])) != 1 for name in self.headers):
            raise _RequestRejected("duplicate request headers are prohibited")
        if any(
            "\r" in name or "\n" in name or "\r" in value or "\n" in value or value != value.strip()
            for name, value in self.headers.items()
        ):
            raise _RequestRejected("request headers are not canonical single lines")
        host = self.headers.get("Host", "").lower()
        expected_hosts = {"stinger-credential-broker", "stinger-credential-broker:8765"}
        if host not in expected_hosts:
            raise _RequestRejected("host header does not name the broker")
        route = next(
            (
                item
                for item in self.config["path_mappings"]
                if item["agent_path"] == target and "POST" in item["methods"]
            ),
            None,
        )
        if route is None:
            raise _RequestRejected("request path is not provider-allowlisted")
        expected_auth = (
            f"Bearer {self.lease}"
            if self.config["injected_auth_header"] == "authorization"
            else self.lease
        )
        inbound_auth = self.headers.get(self.config["injected_auth_header"], "")
        if inbound_auth != expected_auth:
            raise _RequestRejected("broker lease is missing or invalid")
        if any(name.lower() in HOP_BY_HOP_HEADERS for name in self.headers):
            raise _RequestRejected("hop-by-hop request headers are prohibited")
        prohibited = set(self.config["stripped_agent_headers"]) - {
            self.config["injected_auth_header"],
            "host",
        }
        if any(name.lower() in prohibited for name in self.headers):
            raise _RequestRejected("agent authorization or proxy headers are prohibited")
        return cast(dict[str, Any], route)

    def _request_body(self) -> bytes:
        length_text = self.headers.get("Content-Length")
        if length_text is None or not length_text.isascii() or not length_text.isdigit():
            raise _RequestRejected("request must have one bounded content length")
        if len(length_text) > len(str(MAX_REQUEST_BYTES)):
            raise _RequestRejected("request body exceeds the broker limit")
        length = int(length_text)
        if length_text != str(length) or length > MAX_REQUEST_BYTES:
            raise _RequestRejected("request body exceeds the broker limit")
        body = self.rfile.read(length)
        if len(body) != length:
            raise _RequestRejected("request body ended before its declared length")
        return body

    def _upstream(
        self,
        route: dict[str, Any],
        body: bytes,
    ) -> tuple[int, list[tuple[str, str]], bytes]:
        parsed = urlsplit(self.config["upstream_https_origin"])
        assert parsed.hostname is not None and parsed.port is not None
        connection_type: type[http.client.HTTPConnection]
        if parsed.scheme == "https":
            connection_type = http.client.HTTPSConnection
        else:
            connection_type = http.client.HTTPConnection
        connection = connection_type(parsed.hostname, parsed.port, timeout=120)
        forwarded = set(self.config["forwarded_agent_headers"])
        headers = {name: value for name, value in self.headers.items() if name.lower() in forwarded}
        injected = self.raw_credential
        if self.config["injected_auth_scheme"] == "bearer":
            injected = f"Bearer {injected}"
        headers[self.config["injected_auth_header"]] = injected
        headers["Content-Length"] = str(len(body))
        try:
            connection.request("POST", route["upstream_path"], body=body, headers=headers)
            upstream = connection.getresponse()
            response = upstream.read(MAX_RESPONSE_BYTES + 1)
            if len(response) > MAX_RESPONSE_BYTES:
                raise _RequestRejected("upstream response exceeds the broker limit")
            response_headers = [(name, value) for name, value in upstream.getheaders()]
            if any(
                name.lower() == "content-encoding" and value.lower().strip() not in {"", "identity"}
                for name, value in response_headers
            ):
                raise _RequestRejected("encoded upstream responses are prohibited")
            return upstream.status, response_headers, response
        finally:
            connection.close()

    def _contains_credential(self, value: bytes) -> bool:
        """Detect direct and common reversible encodings of the injected credential."""
        raw = self.raw_credential.encode("utf-8")
        variants = {
            raw,
            raw.hex().encode("ascii"),
            raw.hex().upper().encode("ascii"),
            b64encode(raw),
            b64encode(raw).rstrip(b"="),
            urlsafe_b64encode(raw),
            urlsafe_b64encode(raw).rstrip(b"="),
            quote_from_bytes(raw).encode("ascii"),
            quote_from_bytes(raw).lower().encode("ascii"),
            quote_from_bytes(raw, safe="").encode("ascii"),
            quote_from_bytes(raw, safe="").lower().encode("ascii"),
        }
        return any(candidate and candidate in value for candidate in variants)

    @classmethod
    def _next_request_id(cls) -> int:
        with cls.audit_lock:
            cls.request_sequence += 1
            return cls.request_sequence

    def _audit(self, decision: str, *, reason: str, request_id: int) -> None:
        path = getattr(self, "path", "")
        event = {
            "configuration_sha256": self.config["configuration_sha256"],
            "decision": decision,
            "method": getattr(self, "command", ""),
            "path_sha256": _sha256(path.encode("utf-8", errors="replace")),
            "reason": reason,
            "request_id": request_id,
            "upstream_https_origin": self.config["upstream_https_origin"],
        }
        with self.audit_lock, self.audit_path.open("ab") as stream:
            stream.write(_canonical_bytes(event))

    def _reply(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def log_message(self, format: str, *args: object) -> None:
        """Keep request text out of stderr; the canonical audit is the sole log."""


class _RequestRejected(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def main() -> int:
    """Validate exact config/secret inputs, signal readiness, then serve forever."""
    if len(sys.argv) != 3:
        print("usage: credential_broker_server.py CONFIG AUDIT", file=sys.stderr)
        return 64
    config_path = Path(sys.argv[1])
    audit_path = Path(sys.argv[2])
    try:
        config = _load_configuration(config_path)
        raw = os.environ["STINGER_BROKER_RAW_CREDENTIAL"]
        lease = os.environ["STINGER_BROKER_LEASE"]
    except (BrokerConfigurationError, KeyError) as exc:
        print(f"credential broker refused to start: {exc}", file=sys.stderr)
        return 65
    if (
        not raw
        or raw != raw.strip()
        or "\x00" in raw
        or not lease
        or lease != lease.strip()
        or "\x00" in lease
        or _sha256(lease.encode("utf-8")) != config["lease_sha256"]
        or raw == lease
    ):
        print("credential broker refused invalid credential inputs", file=sys.stderr)
        return 65
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    if audit_path.exists() or audit_path.is_symlink():
        print("credential broker audit destination already exists", file=sys.stderr)
        return 65
    CredentialBrokerHandler.config = config
    CredentialBrokerHandler.raw_credential = raw
    CredentialBrokerHandler.lease = lease
    CredentialBrokerHandler.audit_path = audit_path
    CredentialBrokerHandler.audit_lock = threading.Lock()
    CredentialBrokerHandler.request_sequence = 0
    server = CredentialBrokerHTTPServer(("0.0.0.0", 8765), CredentialBrokerHandler)
    shutdown_started = threading.Event()

    def _shutdown(_signum: int, _frame: object) -> None:
        if shutdown_started.is_set():
            return
        shutdown_started.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    with audit_path.open("xb") as stream:
        stream.write(
            _canonical_bytes(
                {
                    "configuration_sha256": config["configuration_sha256"],
                    "decision": "ready",
                    "listen": "0.0.0.0:8765",
                    "provider": config["provider"],
                }
            )
        )
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()
    with CredentialBrokerHandler.audit_lock, audit_path.open("ab") as stream:
        stream.write(
            _canonical_bytes(
                {
                    "configuration_sha256": config["configuration_sha256"],
                    "decision": "quiesced",
                    "provider": config["provider"],
                    "request_count": CredentialBrokerHandler.request_sequence,
                }
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
