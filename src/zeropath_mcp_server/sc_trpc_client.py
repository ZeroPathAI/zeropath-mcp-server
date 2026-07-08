"""Sync HTTP client for ZeroPath's internal tRPC surface.

Some ZeroPath features (currently the Security Compass integration) are
exposed through the frontend's tRPC procedures rather than the public REST
v2 API served by :mod:`trpc_client`. This client speaks that tRPC wire
format, authenticated with the same credentials as the REST client (it
shares :class:`~.trpc_client.ZeropathConfig` and the same auth headers).

tRPC HTTP wire format (per ``trpc-sveltekit`` + tRPC v10):
    queries     → GET  /trpc/<procedure>?input=<urlencoded JSON payload>
    mutations   → POST /trpc/<procedure>     body: <JSON payload>

The server runs tRPC v10 *without* the superjson transformer, so inputs are
sent as plain JSON (not ``{"json": <payload>}``) and responses come back as
``{"result":{"data":<value>}}`` (no ``.json`` wrapper).

Successful responses: ``{ "result": { "data": <T> } }``
Error responses:      ``{ "error":  { "code", "message", "data": { "code" } } }``
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

import requests

from .trpc_client import (
    CLIENT_HEADER_VALUE,
    LEGACY_CHATKIT_TOKEN_HEADER,
    MCP_TOKEN_HEADER,
    ZeropathConfig,
)

DEFAULT_TIMEOUT_SECONDS = 30


class UpstreamError(RuntimeError):
    """Non-2xx response or tRPC-level error from the ZeroPath backend.

    Surfaces the upstream code/message verbatim — this server runs on the
    customer's machine, so leaking diagnostic detail is fine and helpful.
    """


class TrpcClient:
    """Thin sync tRPC client. One instance per server process.

    Shares :class:`~.trpc_client.ZeropathConfig` with the REST client so the
    same credentials (API token / MCP token / session cookie) authenticate
    both surfaces.
    """

    def __init__(self, config: ZeropathConfig) -> None:
        self._config = config
        self._session = requests.Session()

    @property
    def organization_id(self) -> str | None:
        return self._config.organization_id

    def query(self, procedure: str, payload: Mapping[str, Any]) -> Any:
        encoded = quote(json.dumps(dict(payload)), safe="")
        url = f"{self._config.base_url}/trpc/{procedure}?input={encoded}"
        response = self._session.get(
            url,
            headers=self._headers(),
            timeout=DEFAULT_TIMEOUT_SECONDS,
        )
        return self._unwrap(response, procedure)

    def mutate(self, procedure: str, payload: Mapping[str, Any]) -> Any:
        url = f"{self._config.base_url}/trpc/{procedure}"
        response = self._session.post(
            url,
            json=dict(payload),
            headers=self._headers(),
            timeout=DEFAULT_TIMEOUT_SECONDS,
        )
        return self._unwrap(response, procedure)

    def _headers(self) -> dict[str, str]:
        # Mirror the REST client's auth headers so any configured auth mode
        # (API token, MCP token, or session cookie) works for tRPC too.
        headers = {
            "X-ZeroPath-Client": CLIENT_HEADER_VALUE,
            "Content-Type": "application/json",
        }
        if self._config.token_id and self._config.token_secret:
            headers["X-ZeroPath-API-Token-Id"] = self._config.token_id
            headers["X-ZeroPath-API-Token-Secret"] = self._config.token_secret
        if self._config.mcp_token:
            headers[MCP_TOKEN_HEADER] = self._config.mcp_token
            headers[LEGACY_CHATKIT_TOKEN_HEADER] = self._config.mcp_token
        if self._config.session_cookie:
            headers["Cookie"] = self._config.session_cookie
        return headers

    @staticmethod
    def _unwrap(response: requests.Response, procedure: str) -> Any:
        try:
            body = response.json()
        except ValueError:
            raise UpstreamError(
                f"{procedure}: HTTP {response.status_code} (non-JSON response: "
                f"{response.text[:500]!r})"
            ) from None

        if isinstance(body, dict) and "error" in body:
            err = body["error"]
            if isinstance(err, dict):
                # Extract the human code + message; carry the platform-level
                # `data.code` (e.g. UNAUTHORIZED, CONFLICT, BAD_REQUEST)
                # when present.
                code = err.get("data", {}).get("code") or err.get("code") or "ERROR"
                message = err.get("message") or "unknown error"
                raise UpstreamError(f"{procedure}: {code}: {message}")
            raise UpstreamError(f"{procedure}: {err!r}")

        if response.status_code >= 400:
            raise UpstreamError(f"{procedure}: HTTP {response.status_code}")

        if not isinstance(body, dict):
            return body
        return body.get("result", {}).get("data")
