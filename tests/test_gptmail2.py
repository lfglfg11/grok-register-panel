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
    def __init__(self, payload, status_code=200, headers=None):
        self.payload = payload
        self.status_code = status_code
        self.headers = headers or {}

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
        raw_token, mailbox_sid = gptmail2._unpack_inbox_access(token)
        assert raw_token == "inbox-token"
        assert mailbox_sid == "sid"
        assert code == "ABC-123"
        assert [item[0] for item in calls] == ["POST", "GET"]


def test_create_mailbox_bootstraps_gm_sid_and_reissues_token():
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "sessions.json"
        gptmail2.ensure_session(
            "https://mail.example.test", path=path,
            refresh=lambda _base, _proxy: {"v": "not-a-jwt", "sid": ""}, now=time.time(),
        )
        posts = []

        def http_post(_url, **kwargs):
            posts.append(kwargs)
            if len(posts) == 1:
                return FakeResponse(
                    {"success": True, "auth": {"token": "pre-session-token"}},
                    headers={"Set-Cookie": "gm_sid=session-cookie; Path=/; HttpOnly; Secure"},
                )
            return FakeResponse({"success": True, "auth": {"token": "session-token"}})

        email, token = gptmail2.create_mailbox(
            lambda *_args, **_kwargs: None,
            http_post,
            "https://mail.example.test",
            path=path,
            domain="mail.example.test",
        )

        assert email.endswith("@mail.example.test")
        raw_token, mailbox_sid = gptmail2._unpack_inbox_access(token)
        assert raw_token == "session-token"
        assert mailbox_sid == "session-cookie"
        assert len(posts) == 2
        assert posts[0]["headers"]["Cookie"].endswith("gm_sid=")
        assert "gm_sid=session-cookie" in posts[1]["headers"]["Cookie"]
        assert gptmail2.ensure_session("https://mail.example.test", path=path)["sid"] == "session-cookie"


def test_poll_diagnostics_are_redacted_and_only_emit_state_changes():
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "sessions.json"
        gptmail2.ensure_session(
            "https://mail.example.test", path=path,
            refresh=lambda _base, _proxy: {"v": "not-a-jwt", "sid": "mailbox-session-secret"},
            now=time.time(),
        )
        email = "private-user@mail.example.test"
        raw_token = "private-inbox-token"
        packed = gptmail2._pack_inbox_access(raw_token, "mailbox-session-secret")
        logs = []
        polls = 0

        def http_get(_url, **_kwargs):
            nonlocal polls
            polls += 1
            messages = [] if polls < 3 else [{
                "subject": "xAI verification",
                "content": "Your verification code is ABC-123",
            }]
            return FakeResponse({"success": True, "data": {"emails": messages}})

        code = gptmail2.wait_for_code(
            http_get, "https://mail.example.test", email, packed, path=path,
            raise_if_cancelled=lambda callback: None,
            sleep_with_cancel=lambda seconds, callback: None,
            log_callback=logs.append,
        )

        diagnostic = [line for line in logs if line.startswith("[GPTMail2诊断]")]
        joined = "\n".join(diagnostic)
        assert code == "ABC-123"
        assert len(diagnostic) == 3
        assert "messages=0" in diagnostic[1]
        assert "messages=1" in diagnostic[2]
        assert email not in joined
        assert raw_token not in joined
        assert "mailbox-session-secret" not in joined


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
    test_create_mailbox_bootstraps_gm_sid_and_reissues_token()
    test_poll_diagnostics_are_redacted_and_only_emit_state_changes()
    test_domain_pool_sync_is_throttled_for_three_hours()
    print("OK gptmail2")
