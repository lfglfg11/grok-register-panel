# -*- coding: utf-8 -*-
from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from email_providers import gptmail2


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def json(self):
        return self.payload


def test_session_is_cached_per_proxy_and_refreshes_one_hour_early():
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "sessions.json"
        calls = []

        def refresh(_base, proxy):
            calls.append(proxy)
            return {"v": "not-a-jwt", "sid": "session"}

        first = gptmail2.ensure_session(
            "https://mail.example.test", proxy_url="http://proxy-a", path=path,
            refresh=refresh, now=1_000,
        )
        second = gptmail2.ensure_session(
            "https://mail.example.test", proxy_url="http://proxy-a", path=path,
            refresh=refresh, now=1_001,
        )
        gptmail2.ensure_session(
            "https://mail.example.test", proxy_url="http://proxy-b", path=path,
            refresh=refresh, now=1_001,
        )
        gptmail2.ensure_session(
            "https://mail.example.test", proxy_url="http://proxy-a", path=path,
            refresh=refresh, now=1_000 + gptmail2.FALLBACK_TTL_SECONDS - gptmail2.REFRESH_BEFORE_SECONDS,
        )

        assert first == second == {"v": "not-a-jwt", "sid": "session"}
        assert calls == ["http://proxy-a", "http://proxy-b", "http://proxy-a"]
        raw = path.read_text(encoding="utf-8")
        assert "proxy-a" not in raw and "proxy-b" not in raw


def test_create_and_poll_use_http_after_cached_verification():
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "sessions.json"
        gptmail2.ensure_session(
            "https://mail.example.test", path=path,
            refresh=lambda _base, _proxy: {"v": "not-a-jwt", "sid": "sid"}, now=time.time(),
        )
        calls = []

        def http_get(url, **kwargs):
            calls.append(("GET", url, kwargs))
            if url.endswith("/api/domains/public"):
                return FakeResponse({"success": True, "data": {"domains": [{"domain_name": "mail.example.test", "is_active": 1}]}})
            if url.endswith("/api/emails"):
                return FakeResponse({"success": True, "data": {"emails": [{"subject": "xAI verification", "content": "Your verification code is ABC-123"}]}})
            raise AssertionError(url)

        def http_post(url, **kwargs):
            calls.append(("POST", url, kwargs))
            assert kwargs["json"]["email"].endswith("@mail.example.test")
            return FakeResponse({"success": True, "auth": {"token": "inbox-token"}})

        email, token = gptmail2.create_mailbox(
            http_get, http_post, "https://mail.example.test", path=path,
            domain="mail.example.test",
        )
        code = gptmail2.wait_for_code(
            http_get, "https://mail.example.test", email, token, path=path,
            raise_if_cancelled=lambda callback: None,
            sleep_with_cancel=lambda seconds, callback: None,
        )
        assert token == "inbox-token"
        assert code == "ABC-123"
        assert [item[0] for item in calls] == ["POST", "GET"]


def test_domain_pool_sync_is_throttled_for_three_hours():
    with tempfile.TemporaryDirectory() as temp:
        current = time.time()
        session_path = Path(temp) / "sessions.json"
        sync_path = Path(temp) / "sync.json"
        gptmail2.ensure_session(
            "https://mail.example.test", path=session_path,
            refresh=lambda _base, _proxy: {"v": "not-a-jwt", "sid": "sid"}, now=current,
        )
        imports = []

        def http_get(_url, **_kwargs):
            return FakeResponse({"success": True, "data": {"domains": [
                {"domain_name": "a.example.test", "is_active": 1},
                {"domain_name": "b.example.test", "is_active": 1},
            ]}})

        def import_domains(domains, provider, **kwargs):
            imports.append((domains, provider, kwargs))
            return {"ok": True, "imported_count": len(domains), "duplicate_count": 0}

        first = gptmail2.sync_domain_pool(
            http_get, import_domains, "https://mail.example.test", session_path=session_path,
            state_path=sync_path, now=current,
        )
        second = gptmail2.sync_domain_pool(
            http_get, import_domains, "https://mail.example.test", session_path=session_path,
            state_path=sync_path, now=current + 1,
        )
        third = gptmail2.sync_domain_pool(
            http_get, import_domains, "https://mail.example.test", session_path=session_path,
            state_path=sync_path, now=current + gptmail2.DOMAIN_SYNC_INTERVAL_SECONDS,
        )
        assert first["synced"] is True and second["synced"] is False and third["synced"] is True
        assert len(imports) == 2
        assert imports[0][1] == "gptmail2" and imports[0][2]["source"] == "gptmail2-auto"


if __name__ == "__main__":
    test_session_is_cached_per_proxy_and_refreshes_one_hour_early()
    test_create_and_poll_use_http_after_cached_verification()
    test_domain_pool_sync_is_throttled_for_three_hours()
    print("OK gptmail2")
