"""Sync HTTP client for ZeroPath's v1 tRPC surface.

Some ZeroPath features (currently the Security Compass integration) are
exposed through the frontend's tRPC procedures rather than the public REST
v1 API. This client speaks that wire format, authenticated with the same
API token the REST tools use.

tRPC HTTP wire format (per `trpc-sveltekit` + tRPC v10):
    queries     → GET  /trpc/<procedure>?input=<urlencoded JSON payload>
    mutations   → POST /trpc/<procedure>     body: <JSON payload>

Successful responses: ``{ "result": { "data": <T> } }``
Error responses:      ``{ "error":  { "code", "message", "data": { "code" } } }``
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import requests

API_TOKEN_ID_HEADER = "X-ZeroPath-API-Token-Id"
API_TOKEN_SECRET_HEADER = "X-ZeroPath-API-Token-Secret"
CLIENT_HEADER_VALUE = "zeropath-mcp-server"
DEFAULT_TIMEOUT_SECONDS = 30


@dataclass(frozen=True)
class Config:
    base_url: str
    token_id: str
    token_secret: str
    organization_id: str


class UpstreamError(RuntimeError):
    """Non-2xx response or tRPC-level error from the ZeroPath backend.

    Surfaces the upstream code/message verbatim — this server runs on the
    customer's machine, so leaking diagnostic detail is fine and helpful.
    """


class TrpcClient:
    """Thin sync tRPC client. One instance per server process."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._session = requests.Session()

    @property
    def organization_id(self) -> str:
        return self._config.organization_id

    def query(self, procedure: str, payload: Mapping[str, Any]) -> Any:
        # The server runs tRPC v10 *without* the superjson transformer, so
        # inputs are sent as plain JSON (not `{"json": <payload>}`) and
        # responses come back as `{"result":{"data":<value>}}` (no `.json`
        # wrapper). See `src/typescript/frontend/src/lib/trpc/server.ts`.
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
        return {
            API_TOKEN_ID_HEADER: self._config.token_id,
            API_TOKEN_SECRET_HEADER: self._config.token_secret,
            "Content-Type": "application/json",
            "User-Agent": CLIENT_HEADER_VALUE,
        }

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
