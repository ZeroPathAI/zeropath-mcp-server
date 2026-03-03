"""
Helpers for calling ZeroPath V2 REST API endpoints.

Despite the module name (kept for import compatibility), this client calls
the stable `/api/v2/` REST surface.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import requests

JsonObject = dict[str, Any]

DEFAULT_TIMEOUT_SECONDS = 30
CLIENT_HEADER_VALUE = "zeropath-mcp-server"
CHATKIT_TOKEN_HEADER = "X-ZeroPath-ChatKit-Token"
MAX_ERROR_BODY_CHARS = 2000
MCP_ERROR_SENTINEL_KEY = "__zeropath_mcp_error__"


@dataclass(frozen=True)
class ZeropathConfig:
    base_url: str
    token_id: str | None
    token_secret: str | None
    session_cookie: str | None
    chatkit_token: str | None
    organization_id: str | None


def load_config() -> ZeropathConfig:
    token_id = os.getenv("ZEROPATH_TOKEN_ID")
    token_secret = os.getenv("ZEROPATH_TOKEN_SECRET")
    session_cookie = os.getenv("ZEROPATH_SESSION_COOKIE")
    chatkit_token = os.getenv("ZEROPATH_CHATKIT_TOKEN")
    organization_id = os.getenv("ZEROPATH_ORG_ID")
    base_url = os.getenv("ZEROPATH_BASE_URL", "https://zeropath.com")

    if (token_id and not token_secret) or (token_secret and not token_id):
        raise OSError(
            "ZEROPATH_TOKEN_ID and ZEROPATH_TOKEN_SECRET must both be set when using API token authentication"
        )

    auth_mode_count = int(bool(token_id and token_secret)) + int(bool(chatkit_token)) + int(bool(session_cookie))

    if auth_mode_count == 0:
        raise OSError(
            "Missing required credentials: set either "
            "ZEROPATH_TOKEN_ID+ZEROPATH_TOKEN_SECRET, ZEROPATH_CHATKIT_TOKEN, "
            "or ZEROPATH_SESSION_COOKIE"
        )
    if auth_mode_count > 1:
        raise OSError(
            "Ambiguous credentials: configure exactly one auth mode among "
            "ZEROPATH_TOKEN_ID+ZEROPATH_TOKEN_SECRET, ZEROPATH_CHATKIT_TOKEN, "
            "or ZEROPATH_SESSION_COOKIE"
        )

    return ZeropathConfig(
        base_url=base_url.rstrip("/"),
        token_id=token_id,
        token_secret=token_secret,
        session_cookie=session_cookie,
        chatkit_token=chatkit_token,
        organization_id=organization_id,
    )


def make_error(
    code: str,
    message: Any,
    *,
    data: Mapping[str, Any] | None = None,
    http_status: int | None = None,
) -> JsonObject:
    normalized_message = str(message).strip() if message is not None else ""
    if not normalized_message:
        normalized_message = "Unknown error"

    error: JsonObject = {
        "code": code,
        "message": normalized_message,
    }
    if data:
        error["data"] = dict(data)
    if http_status is not None:
        error["httpStatus"] = http_status
    return {MCP_ERROR_SENTINEL_KEY: True, "error": error}


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
    ) -> JsonObject:
        """Call a ZeroPath REST API endpoint.

        V2 endpoints are called directly and the response JSON is returned.
        """
        method = http_method.upper()
        if method == "GET" and payload:
            return make_error(
                "BAD_REQUEST",
                "GET endpoints do not support request bodies in this client; use POST or send an empty payload",
            )

        url = f"{self._config.base_url}{http_path}"
        headers = self._build_headers()

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
            body_preview = response.text[:MAX_ERROR_BODY_CHARS]
            return make_error(
                "BAD_RESPONSE",
                "ZeroPath returned non-JSON response",
                data={"body": body_preview},
                http_status=response.status_code,
            )

        # REST handlers return errors as {"error": "message"} with non-200 status
        if response.status_code >= 400:
            error_message = f"ZeroPath API returned HTTP {response.status_code}"
            error_data: dict[str, Any] = {"response": response_json}

            if isinstance(response_json, dict):
                if "error" in response_json:
                    error_field = response_json.get("error")
                    error_message = _extract_error_message(error_field, fallback=error_message)
                    if isinstance(error_field, dict):
                        if "code" in error_field:
                            error_data["apiCode"] = error_field["code"]
                        if "data" in error_field:
                            error_data["apiData"] = error_field["data"]
                        if "requestId" in error_field:
                            error_data["requestId"] = error_field["requestId"]
                elif "message" in response_json:
                    error_message = _extract_error_message(response_json.get("message"), fallback=error_message)
                else:
                    error_message = _extract_error_message(response_json, fallback=error_message)
            else:
                error_message = _extract_error_message(response_json, fallback=error_message)

            if isinstance(response_json, dict):
                raw_error = response_json.get("error")
                if isinstance(raw_error, str) and not raw_error.strip():
                    error_data["emptyErrorField"] = True

            return make_error(
                "API_ERROR",
                error_message,
                data=error_data,
                http_status=response.status_code,
            )

        return response_json

    def fetch_manifest(self) -> JsonObject:
        """Fetch the MCP tool manifest from the frontend."""
        url = f"{self._config.base_url}/mcp-manifest.json"

        try:
            response = requests.get(
                url,
                headers=self._build_headers(include_content_type=False),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
        except requests.RequestException as exc:
            raise RuntimeError(f"Failed to fetch MCP manifest from {url}: {exc}") from exc

        if response.status_code != 200:
            raise RuntimeError(f"MCP manifest returned HTTP {response.status_code}: {response.text[:200]}")

        try:
            data = response.json()
        except ValueError as exc:
            raise RuntimeError(f"MCP manifest returned non-JSON response: {response.text[:200]}") from exc

        if not isinstance(data, dict) or data.get("version") != 2:
            raise RuntimeError(
                f"Unsupported manifest version: {data.get('version') if isinstance(data, dict) else 'unknown'} (expected 2)"
            )

        return data

    def _build_headers(self, *, include_content_type: bool = True) -> dict[str, str]:
        headers = {
            "X-ZeroPath-Client": CLIENT_HEADER_VALUE,
        }

        if include_content_type:
            headers["Content-Type"] = "application/json"

        if self._config.token_id and self._config.token_secret:
            headers["X-ZeroPath-API-Token-Id"] = self._config.token_id
            headers["X-ZeroPath-API-Token-Secret"] = self._config.token_secret

        if self._config.chatkit_token:
            headers[CHATKIT_TOKEN_HEADER] = self._config.chatkit_token

        if self._config.session_cookie:
            headers["Cookie"] = self._config.session_cookie

        return headers


def _extract_error_message(raw: Any, *, fallback: str) -> str:
    """Return a non-empty error message string from any error payload shape."""
    if isinstance(raw, str):
        message = raw.strip()
        return message if message else fallback

    if isinstance(raw, Mapping):
        for key in ("message", "detail", "error", "title"):
            value = raw.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

        serialized = _safe_json_dump(raw)
        if serialized and serialized != "{}":
            return f"{fallback}: {serialized}"
        return fallback

    if raw is None:
        return fallback

    rendered = str(raw).strip()
    return rendered if rendered else fallback


def _safe_json_dump(value: Any) -> str:
    try:
        dumped = json.dumps(value, default=str)
    except Exception:
        return str(value)
    return dumped[:MAX_ERROR_BODY_CHARS]
