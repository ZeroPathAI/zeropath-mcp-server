"""
Helpers for calling ZeroPath tRPC V2 procedures.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Mapping, TypeAlias
import os
import json as _json

import requests

JsonObject = dict[str, Any]

DEFAULT_TIMEOUT_SECONDS = 30
CLIENT_HEADER_VALUE = "zeropath-mcp-server"

ProcedureType: TypeAlias = Literal["query", "mutation"]


@dataclass(frozen=True)
class ZeropathConfig:
    base_url: str
    token_id: str
    token_secret: str
    organization_id: str


def load_config() -> ZeropathConfig:
    token_id = os.getenv("ZEROPATH_TOKEN_ID")
    token_secret = os.getenv("ZEROPATH_TOKEN_SECRET")
    organization_id = os.getenv("ZEROPATH_ORG_ID")
    base_url = os.getenv("ZEROPATH_BASE_URL", "https://zeropath.com")

    missing = [
        name
        for name, value in (
            ("ZEROPATH_TOKEN_ID", token_id),
            ("ZEROPATH_TOKEN_SECRET", token_secret),
            ("ZEROPATH_ORG_ID", organization_id),
        )
        if not value
    ]

    if missing:
        raise EnvironmentError(
            "Missing required environment variables: " + ", ".join(missing)
        )

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
    def organization_id(self) -> str:
        return self._config.organization_id

    def call(self, procedure: str, payload: Mapping[str, Any], *, procedure_type: ProcedureType) -> JsonObject:
        """Call a tRPC procedure using tRPC v10 HTTP conventions.

        Based on the frontend's `tests/smoke/helpers/trpc.ts`:
        - queries: GET /trpc/<procedure>?input=<url-encoded JSON>
        - mutations: POST /trpc/<procedure> with raw JSON body (NOT wrapped in {"json": ...})
        """
        url = f"{self._config.base_url}/trpc/{procedure}"
        headers = {
            "X-ZeroPath-API-Token-Id": self._config.token_id,
            "X-ZeroPath-API-Token-Secret": self._config.token_secret,
            "X-ZeroPath-Client": CLIENT_HEADER_VALUE,
            "Content-Type": "application/json",
        }

        try:
            if procedure_type == "query":
                response = requests.get(
                    url,
                    headers=headers,
                    params={"input": _json.dumps(dict(payload))},
                    timeout=DEFAULT_TIMEOUT_SECONDS,
                )
            elif procedure_type == "mutation":
                response = requests.post(
                    url,
                    headers=headers,
                    json=dict(payload),
                    timeout=DEFAULT_TIMEOUT_SECONDS,
                )
            else:
                return make_error(
                    "BAD_REQUEST",
                    "Unsupported tRPC procedure type",
                    data={"procedureType": procedure_type},
                )
        except requests.RequestException as exc:
            return make_error(
                "NETWORK_ERROR",
                "Failed to reach ZeroPath tRPC endpoint",
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

        if isinstance(response_json, dict) and "error" in response_json:
            return {"error": response_json["error"]}

        if (
            isinstance(response_json, dict)
            and "result" in response_json
            and isinstance(response_json["result"], dict)
            and "data" in response_json["result"]
        ):
            return response_json["result"]["data"]

        return make_error(
            "BAD_RESPONSE",
            "ZeroPath returned an unexpected tRPC payload",
            data={"body": response_json},
            http_status=response.status_code,
        )

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

        if not isinstance(data, dict) or data.get("version") != 1:
            raise RuntimeError(
                f"Unsupported manifest version: {data.get('version') if isinstance(data, dict) else 'unknown'}"
            )

        return data
