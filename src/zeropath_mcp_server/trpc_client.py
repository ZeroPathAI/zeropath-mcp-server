"""
Helpers for calling ZeroPath V2 REST API endpoints.

Despite the module name (kept for import compatibility), this client calls
the stable `/api/v2/` REST surface.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping
import os
import requests

JsonObject = dict[str, Any]

DEFAULT_TIMEOUT_SECONDS = 30
CLIENT_HEADER_VALUE = "zeropath-mcp-server"


@dataclass(frozen=True)
class ZeropathConfig:
    base_url: str
    token_id: str
    token_secret: str
    organization_id: str | None


def load_config() -> ZeropathConfig:
    token_id = os.getenv("ZEROPATH_TOKEN_ID", "")
    token_secret = os.getenv("ZEROPATH_TOKEN_SECRET", "")
    organization_id = os.getenv("ZEROPATH_ORG_ID")
    base_url = os.getenv("ZEROPATH_BASE_URL", "https://zeropath.com")

    return ZeropathConfig(
        base_url=base_url.rstrip("/"),
        token_id=token_id,
        token_secret=token_secret,
        organization_id=organization_id,
    )


def make_error(
    code: str,
    message: str,
    *,
    data: Mapping[str, Any] | None = None,
    http_status: int | None = None,
) -> JsonObject:
    error: JsonObject = {
        "code": code,
        "message": message,
    }
    if data:
        error["data"] = dict(data)
    if http_status is not None:
        error["httpStatus"] = http_status
    return {"error": error}


class TrpcClient:
    def __init__(self, config: ZeropathConfig) -> None:
        self._config = config

    @property
    def organization_id(self) -> str | None:
        return self._config.organization_id

    def call(
        self,
        http_path: str,
        payload: Mapping[str, Any],
        *,
        http_method: str = "POST",
        cookies: str | None = None,
    ) -> JsonObject:
        """Call a ZeroPath REST API endpoint.

        When *cookies* is provided (a raw Cookie header string from the user's
        browser session), the request authenticates via session cookies instead
        of API token headers.  This allows the chatkit agent to act on behalf
        of the logged-in user.
        """
        method = http_method.upper()
        if method == "GET" and payload:
            return make_error(
                "BAD_REQUEST",
                "GET endpoints do not support request bodies in this client; use POST or send an empty payload",
            )

        url = f"{self._config.base_url}{http_path}"
        headers: dict[str, str] = {
            "X-ZeroPath-Client": CLIENT_HEADER_VALUE,
            "Content-Type": "application/json",
        }

        if cookies:
            # Authenticate as the logged-in user via session cookies.
            headers["Cookie"] = cookies
        else:
            # Fall back to static API token auth.
            headers["X-ZeroPath-API-Token-Id"] = self._config.token_id
            headers["X-ZeroPath-API-Token-Secret"] = self._config.token_secret

        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=dict(payload) if method != "GET" else None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
        except requests.RequestException as exc:
            return make_error(
                "NETWORK_ERROR",
                f"Failed to reach ZeroPath API endpoint {http_path}",
                data={"detail": str(exc)},
            )

        try:
            response_json = response.json()
        except ValueError:
            return make_error(
                "BAD_RESPONSE",
                "ZeroPath returned non-JSON response",
                data={"body": response.text},
                http_status=response.status_code,
            )

        # REST handlers return errors as {"error": "message"} with non-200 status
        if response.status_code >= 400:
            error_message = (
                response_json.get("error", "Unknown error")
                if isinstance(response_json, dict)
                else str(response_json)
            )
            return make_error(
                "API_ERROR",
                error_message,
                http_status=response.status_code,
            )

        return response_json

    def fetch_manifest(self) -> JsonObject:
        """Fetch the MCP tool manifest from the frontend."""
        url = f"{self._config.base_url}/mcp-manifest.json"

        try:
            response = requests.get(url, timeout=DEFAULT_TIMEOUT_SECONDS)
        except requests.RequestException as exc:
            raise RuntimeError(
                f"Failed to fetch MCP manifest from {url}: {exc}"
            ) from exc

        if response.status_code != 200:
            raise RuntimeError(
                f"MCP manifest returned HTTP {response.status_code}: {response.text[:200]}"
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise RuntimeError(
                f"MCP manifest returned non-JSON response: {response.text[:200]}"
            ) from exc

        if not isinstance(data, dict) or data.get("version") != 2:
            raise RuntimeError(
                f"Unsupported manifest version: {data.get('version') if isinstance(data, dict) else 'unknown'} (expected 2)"
            )

        return data
