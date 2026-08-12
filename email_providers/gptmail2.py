"""GPTMail2 temporary-mail adapter.

The browser-verification cookie is a short-lived credential.  It is kept in a
private, per-proxy cache and Camoufox is started only to create or renew it.
Normal mailbox creation and polling use HTTP requests only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from email_providers.common import extract_verification_code
from secure_files import atomic_write_json, exclusive_file_lock


DEFAULT_BASE_URL = "https://mail.chatgpt.org.uk"
DEFAULT_SESSION_FILE = Path(__file__).resolve().parents[1] / "log" / "gptmail2_sessions.json"
DEFAULT_DOMAIN_SYNC_FILE = Path(__file__).resolve().parents[1] / "log" / "gptmail2_domain_sync.json"
REFRESH_BEFORE_SECONDS = 60 * 60
FALLBACK_TTL_SECONDS = 24 * 60 * 60
DOMAIN_SYNC_INTERVAL_SECONDS = 3 * 60 * 60
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0"
)

HttpGet = Callable[..., Any]
HttpPost = Callable[..., Any]


def normalize_base(base_url: str = "") -> str:
    raw = str(base_url or DEFAULT_BASE_URL).strip().rstrip("/")
    if not raw:
        raise ValueError("GPTMail2 站点 URL 未配置")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("GPTMail2 站点 URL 无效")
    if parsed.username or parsed.password:
        raise ValueError("GPTMail2 站点 URL 不能包含账号密码")
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"


def session_file(path: str | os.PathLike[str] | None = None) -> Path:
    configured = path or os.environ.get("GPTMAIL2_SESSION_FILE")
    return Path(configured).expanduser() if configured else DEFAULT_SESSION_FILE


def domain_sync_file(path: str | os.PathLike[str] | None = None) -> Path:
    configured = path or os.environ.get("GPTMAIL2_DOMAIN_SYNC_FILE")
    return Path(configured).expanduser() if configured else DEFAULT_DOMAIN_SYNC_FILE


def _proxy_key(proxy_url: str) -> str:
    # Do not persist proxy URLs or credentials; only isolate cookie caches by a hash.
    value = str(proxy_url or "direct").strip() or "direct"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]


def _jwt_expiry(value: str) -> int:
    """Accept normal JWT payloads and the provider's historical first-part form."""
    for part in str(value or "").split(".")[:2]:
        if not part:
            continue
        try:
            padded = part + "=" * (-len(part) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
            expiry = int(payload.get("exp") or 0)
            if expiry > 0:
                return expiry
        except Exception:
            continue
    return 0


def _read_state(path: Path) -> dict:
    if not path.exists():
        return {"version": 1, "sessions": {}}
    try:
        value = json.loads(path.read_text(encoding="utf-8") or "{}")
        sessions = value.get("sessions") if isinstance(value, dict) else None
        return {"version": 1, "sessions": sessions if isinstance(sessions, dict) else {}}
    except Exception:
        # A corrupt credential cache must never be trusted.
        return {"version": 1, "sessions": {}}


def _is_fresh(entry: object, now: float) -> bool:
    if not isinstance(entry, dict) or not entry.get("v"):
        return False
    try:
        return float(entry.get("expires_at") or 0) > now + REFRESH_BEFORE_SECONDS
    except (TypeError, ValueError):
        return False


def _headers(base: str, session: dict, *, inbox_token: str = "", referer: str = "") -> dict:
    result = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Origin": base,
        "Referer": referer or f"{base}/zh/",
        "Cookie": f"gptmail_lang=zh; gm_browser_verified={session['v']}; gm_sid={session.get('sid', '')}",
    }
    if inbox_token:
        result["x-inbox-token"] = inbox_token
    return result


def _refresh_in_process(base: str, proxy_url: str) -> dict:
    from camoufox.sync_api import Camoufox

    options: dict[str, Any] = {"headless": False}
    proxy = str(proxy_url or "").strip()
    if proxy:
        parsed = urlparse(proxy if "://" in proxy else "http://" + proxy)
        options["proxy"] = {
            "server": f"{parsed.scheme or 'http'}://{parsed.hostname}" + (f":{parsed.port}" if parsed.port else ""),
        }
        if parsed.username:
            options["proxy"]["username"] = parsed.username
        if parsed.password:
            options["proxy"]["password"] = parsed.password

    with Camoufox(**options) as browser:
        page = browser.new_page()
        page.goto(f"{base}/zh/", wait_until="domcontentloaded", timeout=60_000)
        for _ in range(60):
            cookies = [
                item for item in page.context.cookies()
                if "chatgpt.org.uk" in str(item.get("domain") or "")
            ]
            verified = next((item for item in cookies if item.get("name") == "gm_browser_verified"), None)
            if verified and verified.get("value"):
                sid = next((item for item in cookies if item.get("name") == "gm_sid"), {})
                return {"v": verified["value"], "sid": sid.get("value", "")}
            time.sleep(1)
    raise RuntimeError("GPTMail2 在 60 秒内未获得 gm_browser_verified")


def _refresh_with_xvfb(base: str, proxy_url: str, path: Path) -> None:
    env = os.environ.copy()
    env["GPTMAIL2_SESSION_FILE"] = str(path)
    env["GPTMAIL2_BASE_URL"] = base
    env["GPTMAIL2_REFRESH_CHILD"] = "1"
    if proxy_url:
        env["PROXY"] = proxy_url
    command = ["xvfb-run", "-a", sys.executable, "-m", "email_providers.gptmail2", "--refresh"]
    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError("GPTMail2 Xvfb 续签失败")


def ensure_session(
    base_url: str = "",
    *,
    proxy_url: str = "",
    path: str | os.PathLike[str] | None = None,
    force: bool = False,
    refresh: Optional[Callable[[str, str], dict]] = None,
    now: Optional[float] = None,
) -> dict:
    """Return a valid browser-verification session, refreshing only when needed."""
    base = normalize_base(base_url)
    cache_path = session_file(path)
    cache_key = _proxy_key(proxy_url)
    current = time.time() if now is None else float(now)
    with exclusive_file_lock(cache_path.with_suffix(cache_path.suffix + ".lock")):
        state = _read_state(cache_path)
        existing = state["sessions"].get(cache_key)
        if not force and _is_fresh(existing, current):
            return {"v": str(existing["v"]), "sid": str(existing.get("sid") or "")}

        if refresh is not None:
            created = refresh(base, proxy_url)
        elif sys.platform.startswith("linux") and not os.environ.get("DISPLAY"):
            _refresh_with_xvfb(base, proxy_url, cache_path)
            state = _read_state(cache_path)
            created = state["sessions"].get(cache_key) or {}
        else:
            created = _refresh_in_process(base, proxy_url)

        verified = str(created.get("v") or "").strip()
        if not verified:
            raise RuntimeError("GPTMail2 续签未返回 gm_browser_verified")
        expiry = _jwt_expiry(verified) or int(current + FALLBACK_TTL_SECONDS)
        state["sessions"][cache_key] = {
            "v": verified,
            "sid": str(created.get("sid") or ""),
            "expires_at": int(expiry),
            "updated_at": int(current),
        }
        atomic_write_json(cache_path, state)
        return {"v": verified, "sid": str(created.get("sid") or "")}


def _json(resp: Any, action: str) -> dict:
    status = int(getattr(resp, "status_code", 0) or 0)
    try:
        payload = resp.json()
    except Exception as exc:
        raise RuntimeError(f"GPTMail2 {action}返回非 JSON（HTTP {status}）") from exc
    if status >= 400 or not isinstance(payload, dict) or payload.get("success") is False:
        detail = payload.get("message") or payload.get("error") or f"HTTP {status}"
        raise RuntimeError(f"GPTMail2 {action}失败: {detail}")
    return payload


def _pick_local_part() -> str:
    names = ("perry", "barrett", "porter", "carson", "morgan", "smith", "jones", "williams")
    return f"{random.choice(names)}{random.randint(100, 999)}"


def list_domains(
    http_get: HttpGet,
    base_url: str = "",
    *,
    proxy_url: str = "",
    path: str | os.PathLike[str] | None = None,
) -> list[str]:
    """Read all active public domains using a valid cached verification session."""
    base = normalize_base(base_url)
    session = ensure_session(base, proxy_url=proxy_url, path=path)
    payload = _json(
        http_get(
            f"{base}/api/domains/public", headers=_headers(base, session), timeout=20,
            _allow_direct_fallback=False,
        ),
        "读取域名",
    )
    seen = set()
    domains = []
    for item in ((payload.get("data") or {}).get("domains") or []):
        if not isinstance(item, dict) or int(item.get("is_active") or 0) != 1:
            continue
        domain = str(item.get("domain_name") or "").strip().lower().lstrip("@")
        if domain and domain not in seen:
            seen.add(domain)
            domains.append(domain)
    if not domains:
        raise RuntimeError("GPTMail2 没有可用的公开收信域名")
    return domains


def sync_domain_pool(
    http_get: HttpGet,
    import_domains: Callable[..., dict],
    base_url: str = "",
    *,
    proxy_url: str = "",
    session_path: str | os.PathLike[str] | None = None,
    state_path: str | os.PathLike[str] | None = None,
    force: bool = False,
    now: Optional[float] = None,
) -> dict:
    """Import active GPTMail2 domains once at task start and every three hours."""
    current = time.time() if now is None else float(now)
    cache_path = domain_sync_file(state_path)
    cache_key = hashlib.sha256(
        f"{normalize_base(base_url)}:{_proxy_key(proxy_url)}".encode("utf-8")
    ).hexdigest()[:24]
    with exclusive_file_lock(cache_path.with_suffix(cache_path.suffix + ".lock")):
        state = _read_state(cache_path)
        entry = state["sessions"].get(cache_key) or {}
        try:
            due = current >= float(entry.get("next_sync_at") or 0)
        except (TypeError, ValueError):
            due = True
        if not force and not due:
            return {"synced": False, "reason": "fresh", "next_sync_at": entry.get("next_sync_at")}
        domains = list_domains(
            http_get, base_url, proxy_url=proxy_url, path=session_path
        )
        result = import_domains(domains, "gptmail2", source="gptmail2-auto")
        if not result.get("ok"):
            raise RuntimeError(str(result.get("error") or "GPTMail2 域名池同步失败"))
        next_sync_at = int(current + DOMAIN_SYNC_INTERVAL_SECONDS)
        state["sessions"][cache_key] = {
            "next_sync_at": next_sync_at,
            "last_domain_count": len(domains),
            "updated_at": int(current),
        }
        atomic_write_json(cache_path, state)
        return {
            "synced": True,
            "domain_count": len(domains),
            "imported_count": int(result.get("imported_count") or 0),
            "duplicate_count": int(result.get("duplicate_count") or 0),
            "next_sync_at": next_sync_at,
        }


def create_mailbox(
    http_get: HttpGet,
    http_post: HttpPost,
    base_url: str = "",
    *,
    proxy_url: str = "",
    domain: str = "",
    path: str | os.PathLike[str] | None = None,
) -> tuple[str, str]:
    base = normalize_base(base_url)
    session = ensure_session(base, proxy_url=proxy_url, path=path)
    requested = str(domain or "").strip().lstrip("@")
    if requested:
        selected = requested
    else:
        # Legacy/no-pool fallback only. Normal registration selects a managed
        # domain after sync_domain_pool(), so it never downloads the list here.
        domains = list_domains(http_get, base, proxy_url=proxy_url, path=path)
        selected = random.choice(domains)
    email = f"{_pick_local_part()}@{selected}"
    response = http_post(
        f"{base}/api/inbox-token",
        json={"email": email},
        headers={**_headers(base, session, referer=f"{base}/zh/{email}"), "Content-Type": "application/json"},
        timeout=20,
        _allow_direct_fallback=False,
    )
    try:
        payload = _json(response, "创建收件箱")
    except RuntimeError as exc:
        if "browser_verification" not in str(exc):
            raise
        session = ensure_session(base, proxy_url=proxy_url, path=path, force=True)
        response = http_post(
            f"{base}/api/inbox-token", json={"email": email},
            headers={**_headers(base, session, referer=f"{base}/zh/{email}"), "Content-Type": "application/json"}, timeout=20,
            _allow_direct_fallback=False,
        )
        payload = _json(response, "创建收件箱")
    token = str(((payload.get("auth") or {}).get("token") or "")).strip()
    if not token:
        raise RuntimeError("GPTMail2 创建收件箱响应缺少 inbox token")
    return email, token


def wait_for_code(
    http_get: HttpGet,
    base_url: str,
    email: str,
    inbox_token: str,
    *,
    proxy_url: str = "",
    path: str | os.PathLike[str] | None = None,
    timeout: int = 180,
    poll_interval: int = 3,
    raise_if_cancelled: Callable[[Optional[Callable[[], bool]]], None],
    sleep_with_cancel: Callable[[float, Optional[Callable[[], bool]]], None],
    log_callback: Optional[Callable[[str], None]] = None,
    cancel_callback: Optional[Callable[[], bool]] = None,
    resend_callback: Optional[Callable[[], None]] = None,
) -> str:
    base = normalize_base(base_url)
    deadline = time.time() + max(1, int(timeout))
    next_resend_at = time.time() + 35
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        if resend_callback and time.time() >= next_resend_at:
            try:
                resend_callback()
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] GPTMail2 触发重发验证码失败: {exc}")
            next_resend_at = time.time() + 35
        try:
            session = ensure_session(base, proxy_url=proxy_url, path=path)
            response = http_get(
                f"{base}/api/emails",
                params={"email": email},
                headers=_headers(base, session, inbox_token=inbox_token, referer=f"{base}/zh/{email}"),
                timeout=20,
                _allow_direct_fallback=False,
            )
            payload = _json(response, "读取邮件")
            messages = ((payload.get("data") or {}).get("emails") or [])
            if log_callback:
                log_callback(f"[Debug] GPTMail2 本轮邮件数量: {len(messages)}")
            for message in messages:
                if not isinstance(message, dict):
                    continue
                subject = str(message.get("subject") or "")
                content = str(message.get("content") or message.get("text") or "")
                code = extract_verification_code(content, subject)
                if code:
                    if log_callback:
                        log_callback("[*] GPTMail2 已提取到验证码")
                    return code
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] GPTMail2 拉取邮件失败: {exc}")
        sleep_with_cancel(poll_interval, cancel_callback)
    raise RuntimeError(f"GPTMail2 在 {timeout}s 内未收到验证码邮件")


def _main() -> int:
    if "--refresh" not in sys.argv or os.environ.get("GPTMAIL2_REFRESH_CHILD") != "1":
        return 2
    base = normalize_base(os.environ.get("GPTMAIL2_BASE_URL", ""))
    proxy_url = os.environ.get("PROXY", "")
    cache_path = session_file(os.environ.get("GPTMAIL2_SESSION_FILE"))
    created = _refresh_in_process(base, proxy_url)
    verified = str(created.get("v") or "").strip()
    if not verified:
        raise RuntimeError("GPTMail2 续签未返回 gm_browser_verified")
    state = _read_state(cache_path)
    state["sessions"][_proxy_key(proxy_url)] = {
        "v": verified,
        "sid": str(created.get("sid") or ""),
        "expires_at": _jwt_expiry(verified) or int(time.time() + FALLBACK_TTL_SECONDS),
        "updated_at": int(time.time()),
    }
    atomic_write_json(cache_path, state)
    return 0


if __name__ == "__main__":  # pragma: no cover - subprocess entry point
    raise SystemExit(_main())
