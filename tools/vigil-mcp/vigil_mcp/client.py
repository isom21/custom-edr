"""Thin async REST client for the Vigil manager.

Authentication modes:
  * `VIGIL_API_TOKEN` (preferred) — long-lived bearer token issued via
    `POST /api/tokens`. Sent as `Authorization: Bearer <token>`.
  * `VIGIL_EMAIL` + `VIGIL_PASSWORD` — JWT login flow. The client logs
    in lazily, keeps the access token in memory, and refreshes via
    `/api/auth/refresh` on the first 401.

All API surface is exposed through small helper methods that return
parsed JSON. Errors raise `VigilApiError` with status + detail so the
MCP layer can surface them verbatim to the operator.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Any

import httpx


class VigilApiError(RuntimeError):
    def __init__(self, status: int, detail: str, path: str):
        super().__init__(f"{status} {path}: {detail}")
        self.status = status
        self.detail = detail
        self.path = path


@dataclass
class _LoginCreds:
    email: str
    password: str


class VigilClient:
    def __init__(
        self,
        *,
        base_url: str,
        api_token: str | None = None,
        login: _LoginCreds | None = None,
        timeout_s: float = 30.0,
    ):
        if not api_token and not login:
            raise ValueError(
                "VigilClient requires either api_token or login credentials"
            )
        self._base_url = base_url.rstrip("/")
        self._api_token = api_token
        self._login = login
        self._access: str | None = None
        self._refresh: str | None = None
        self._lock = asyncio.Lock()
        self._http = httpx.AsyncClient(timeout=timeout_s)

    # -- auth -----------------------------------------------------------------

    async def _ensure_token(self) -> str:
        if self._api_token:
            return self._api_token
        async with self._lock:
            if self._access:
                return self._access
            assert self._login is not None
            r = await self._http.post(
                f"{self._base_url}/api/auth/login",
                json={"email": self._login.email, "password": self._login.password},
                headers={"Accept": "application/json"},
            )
            if r.status_code != 200:
                raise VigilApiError(r.status_code, r.text, "/api/auth/login")
            data = r.json()
            self._access = data["access_token"]
            self._refresh = data.get("refresh_token")
            return self._access

    async def _try_refresh(self) -> bool:
        if not self._refresh:
            return False
        async with self._lock:
            r = await self._http.post(
                f"{self._base_url}/api/auth/refresh",
                json={"refresh_token": self._refresh},
                headers={"Accept": "application/json"},
            )
            if r.status_code != 200:
                self._access = None
                self._refresh = None
                return False
            data = r.json()
            self._access = data["access_token"]
            self._refresh = data.get("refresh_token", self._refresh)
            return True

    # -- request --------------------------------------------------------------

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
    ) -> Any:
        token = await self._ensure_token()
        url = f"{self._base_url}{path}"
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        if json is not None:
            headers["Content-Type"] = "application/json"
        r = await self._http.request(
            method, url, params=params, json=json, headers=headers
        )
        if r.status_code == 401 and not self._api_token and await self._try_refresh():
            token = await self._ensure_token()
            headers["Authorization"] = f"Bearer {token}"
            r = await self._http.request(
                method, url, params=params, json=json, headers=headers
            )
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail", r.text)
            except Exception:
                detail = r.text
            raise VigilApiError(r.status_code, str(detail), path)
        if r.status_code == 204 or not r.content:
            return None
        return r.json()

    async def aclose(self) -> None:
        await self._http.aclose()

    # -- helper factories -----------------------------------------------------

    @classmethod
    def from_env(cls) -> "VigilClient":
        base = os.environ.get("VIGIL_BASE_URL", "http://localhost:8000")
        token = os.environ.get("VIGIL_API_TOKEN")
        if token:
            return cls(base_url=base, api_token=token)
        email = os.environ.get("VIGIL_EMAIL")
        password = os.environ.get("VIGIL_PASSWORD")
        if email and password:
            return cls(base_url=base, login=_LoginCreds(email=email, password=password))
        raise SystemExit(
            "Set VIGIL_API_TOKEN, or VIGIL_EMAIL + VIGIL_PASSWORD, before starting the MCP."
        )
