"""AI model provider layer: optional, with the user's own keys.

Privacy Protector works fully without any model: the local classifier, the
built-in rules and your own decisions protect you. Models only add a second
reading of domains the local engine cannot settle.

To turn them on, add one or more providers in Settings, or write them to
``<data dir>/ai-providers.json`` (never committed, never sent anywhere but the
provider you name)::

    {"enabled": true,
     "providers": [
        {"name": "openai", "kind": "openai", "baseUrl": "https://api.openai.com/v1",
         "model": "<a model your key can call>", "apiKey": "sk-...",
         "roles": ["writer", "juror", "judge"], "enabled": true, "dailyLimit": 300},
        {"name": "claude", "kind": "anthropic", "baseUrl": "https://api.anthropic.com/v1",
         "model": "<a Claude model id>", "apiKeyEnv": "ANTHROPIC_API_KEY",
         "roles": ["judge"], "enabled": true}
     ]}

``kind`` is ``openai`` for any OpenAI-compatible endpoint (OpenAI, DeepSeek,
Groq, Mistral, OpenRouter, a local Ollama at http://127.0.0.1:11434/v1, ...) or
``anthropic``. The review has three roles, and one provider may hold all three:

- writer: reads each new domain first and proposes a verdict,
- juror: decides block / monitor / allow, in rotation among jurors, preferring
  a provider other than the writer,
- judge: confirms or overturns the jury before anything is blocked.

Slots: ``auto`` rotates among writers, or among jurors when the call excludes
the ``writer`` role; ``judge`` is the first enabled judge. A provider can also
be called by its own name. ``dailyLimit`` caps calls per provider per local day.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import paths

USER_AGENT = "PrivacyProtector-DomainReview/2.0"
DEFAULT_TIMEOUT = 60.0
GATEWAY_URL = ""   # kept for importers; there is no gateway in this edition
PROJECT_NAME = "Privacy Protector"
DEFAULT_TASK = "Domain Review"
CONFIG_PATH = paths.DATA_ROOT / "ai-providers.json"
COOLDOWN_SECONDS = 90.0
DAILY_COOLDOWN_SECONDS = 6 * 3600.0
BALANCE_COOLDOWN_SECONDS = 6 * 3600.0
_DAILY_QUOTA_MARKERS = ("perday", "per day", "daily limit", "requests per day")
ROLES = ("writer", "juror", "judge")
AUTO = "auto"
JUDGE_SLOT = "judge"
PREFERRED_ORDER = (AUTO,)
# Kept for importers: the writer and the judge are the review group.
REVIEW_GROUP = ("writer", "judge")
EXTRA_VOTES = len(REVIEW_GROUP) - 1


def _is_daily_quota(detail: str) -> bool:
    text = str(detail or "").lower()
    return any(marker in text for marker in _DAILY_QUOTA_MARKERS)


# A daily cap pauses a slot until local midnight, so it is not retried all day.
_DAILY_CAP_MARKERS = (":budget", ":daily-limit")
PAUSE_AFTER_MIDNIGHT_SECONDS = 300.0
_paused_until: dict[str, float] = {}
_paused_why: dict[str, str] = {}


def next_local_midnight(now: float | None = None) -> float:
    """The next local midnight plus five minutes."""
    import datetime as _dt

    local = _dt.datetime.fromtimestamp(now if now is not None else time.time()).astimezone()
    midnight = (local + _dt.timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return midnight.timestamp() + PAUSE_AFTER_MIDNIGHT_SECONDS


def substitute_reason(slot: str, data: Any) -> str:
    """Kept for importers: with direct providers nobody answers in another slot's place."""
    return ""


def is_daily_cap(reason: str) -> bool:
    return any(marker in str(reason or "") for marker in _DAILY_CAP_MARKERS)


def pause_slot(slot: str, reason: str, now: float | None = None) -> float:
    """Pauses the slot until midnight if the reason is its daily cap; returns the time it comes back (0 otherwise)."""
    if not is_daily_cap(reason):
        return 0.0
    until = next_local_midnight(now)
    _paused_until[slot], _paused_why[slot] = until, reason
    return until


def _all_paused(errors: list[str]) -> bool:
    return bool(errors) and all("Suspended until midnight" in e for e in errors)


def slot_paused(slot: str, now: float | None = None) -> str:
    if (now if now is not None else time.time()) < _paused_until.get(slot, 0.0):
        return _paused_why.get(slot, "daily limit")
    _paused_until.pop(slot, None)
    return ""


# ---------------------------------------------------------------------------
# User configuration
# ---------------------------------------------------------------------------

@dataclass
class ProviderConfig:
    name: str
    kind: str
    base_url: str
    model: str
    api_key: str = ""
    roles: tuple[str, ...] = ROLES
    enabled: bool = True
    daily_limit: int = 0
    minimum_interval: float = 1.0
    paid: bool = True

    def public(self) -> dict[str, Any]:
        return {"name": self.name, "kind": self.kind, "baseUrl": self.base_url, "model": self.model,
                "roles": list(self.roles), "enabled": self.enabled, "dailyLimit": self.daily_limit,
                "hasKey": bool(self.api_key)}


def load_config(path: Any = None) -> dict[str, Any]:
    target = path or CONFIG_PATH
    try:
        data = json.loads(open(target, encoding="utf-8").read())
    except (OSError, ValueError):
        return {"enabled": False, "providers": []}
    return data if isinstance(data, dict) else {"enabled": False, "providers": []}


def save_config(data: dict[str, Any], path: Any = None) -> None:
    target = Path(path or CONFIG_PATH)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, target)


def configured_providers(config: dict[str, Any] | None = None) -> list[ProviderConfig]:
    """Enabled providers with a key (or a local endpoint that needs none), in the order the user listed them."""
    data = config if config is not None else load_config()
    if not data.get("enabled", True):
        return []
    out: list[ProviderConfig] = []
    for raw in data.get("providers") or []:
        if not isinstance(raw, dict) or not raw.get("enabled", True):
            continue
        name = str(raw.get("name") or "").strip()
        kind = str(raw.get("kind") or "openai").strip().lower()
        base = str(raw.get("baseUrl") or "").strip().rstrip("/")
        model = str(raw.get("model") or "").strip()
        key = str(raw.get("apiKey") or "")
        if not key and raw.get("apiKeyEnv"):
            key = os.environ.get(str(raw["apiKeyEnv"]), "")
        local = base.startswith(("http://127.0.0.1", "http://localhost"))
        if not name or not base or not model or kind not in ("openai", "anthropic") or not (key or local):
            continue
        roles = tuple(r for r in (raw.get("roles") or ROLES) if r in ROLES) or ROLES
        out.append(ProviderConfig(name, kind, base, model, key, roles, True, int(raw.get("dailyLimit") or 0),
                                  float(raw.get("minimumInterval") or 1.0), not local))
    return out


def role_names(role: str) -> tuple[str, ...]:
    return tuple(p.name for p in configured_providers() if role in p.roles)


def available_providers() -> set[str]:
    return {p.name for p in configured_providers()}


def enabled() -> bool:
    return bool(configured_providers())


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def _post_json(url: str, payload: dict[str, Any], headers: dict[str, str],
               timeout: float = DEFAULT_TIMEOUT) -> tuple[int, dict[str, Any] | None, str]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/json; charset=utf-8")
    request.add_header("User-Agent", USER_AGENT)
    for header, value in headers.items():
        request.add_header(header, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            text = response.read().decode("utf-8", "replace")
            try:
                return response.status, json.loads(text), ""
            except ValueError:
                return response.status, None, text[:300]
    except urllib.error.HTTPError as exc:
        return exc.code, None, exc.read().decode("utf-8", "replace")[:300]
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        return 0, None, str(exc)[:200]


def _error_label(slot: str, status: int, detail: str) -> str:
    label = f"{slot} HTTP {status}"
    return label + (" " + " ".join(str(detail or "").split())[:60] if status == 0 and detail else "")


def _content_parse(data: dict[str, Any]) -> str:
    choices = data.get("choices") or []
    if not choices:
        return ""
    return str((choices[0].get("message") or {}).get("content") or "")


_openai_parse = _content_parse


def provider_complete(config: ProviderConfig, system: str, prompt: str, max_tokens: int, temperature: float,
                      *, json_mode: bool = True, timeout: float = DEFAULT_TIMEOUT) -> tuple[int, Any, str]:
    """One call to one provider. The reply is returned in OpenAI chat format whatever the provider."""
    if config.kind == "anthropic":
        payload = {"model": config.model, "max_tokens": max_tokens, "temperature": temperature, "system": system,
                   "messages": [{"role": "user", "content": prompt}]}
        headers = {"x-api-key": config.api_key, "anthropic-version": "2023-06-01"}
        status, data, detail = _post_json(config.base_url + "/messages", payload, headers, timeout)
        if status == 200 and isinstance(data, dict):
            text = "".join(str(part.get("text") or "") for part in data.get("content") or [] if isinstance(part, dict))
            data = {"choices": [{"message": {"content": text}}], "usage": data.get("usage")}
        return status, data, detail
    payload = {"model": config.model, "max_tokens": max_tokens, "temperature": temperature,
               "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}]}
    if json_mode:
        payload["response_format"] = {"type": "json_object"}
    headers = {"Authorization": "Bearer " + config.api_key} if config.api_key else {}
    return _post_json(config.base_url + "/chat/completions", payload, headers, timeout)


# ---------------------------------------------------------------------------
# Daily limits
# ---------------------------------------------------------------------------

_usage_lock = threading.Lock()
_usage: dict[str, Any] = {"day": "", "calls": {}}


def _today() -> str:
    return time.strftime("%Y-%m-%d")


def _count_call(name: str, limit: int) -> bool:
    """Counts one call; False when the provider already used its daily limit."""
    with _usage_lock:
        if _usage["day"] != _today():
            _usage["day"], _usage["calls"] = _today(), {}
        used = _usage["calls"].get(name, 0)
        if limit and used >= limit:
            return False
        _usage["calls"][name] = used + 1
        return True


def usage_today() -> dict[str, int]:
    with _usage_lock:
        return dict(_usage["calls"]) if _usage["day"] == _today() else {}


# ---------------------------------------------------------------------------
# Pool
# ---------------------------------------------------------------------------

@dataclass
class ProviderState:
    config: ProviderConfig
    calls: int = 0
    failures: int = 0
    total_seconds: float = 0.0
    cooldown_until: float = 0.0
    next_allowed_at: float = 0.0
    last_error: str = ""
    exhausted_daily: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def name(self) -> str:
        return self.config.name

    @property
    def model(self) -> str:
        return self.config.model

    @property
    def slot(self) -> str:
        return self.config.name + ":" + self.config.model

    @property
    def available_at(self) -> float:
        return max(self.cooldown_until, self.next_allowed_at)

    @property
    def ready(self) -> bool:
        return time.monotonic() >= self.available_at

    def snapshot(self) -> dict[str, Any]:
        return {
            "provider": self.name, "model": self.model, "slot": self.slot, "roles": list(self.config.roles),
            "calls": self.calls, "failures": self.failures,
            "averageSeconds": round(self.total_seconds / self.calls, 2) if self.calls else 0.0,
            "ready": self.ready, "cooldownSeconds": max(0, round(self.available_at - time.monotonic())),
            "lastError": self.last_error, "exhaustedDaily": self.exhausted_daily,
            "dailyLimit": self.config.daily_limit, "usedToday": usage_today().get(self.name, 0),
        }


# States live across pools so cooldowns and rotation survive between calls.
_states: dict[str, ProviderState] = {}
_states_lock = threading.Lock()
_rotation = {"writer": 0, "juror": 0}


def _state_for(config: ProviderConfig) -> ProviderState:
    with _states_lock:
        state = _states.get(config.name)
        if state is None or state.config != config:
            state = _states[config.name] = ProviderState(config=config)
        return state


class ProviderPool:
    """The configured providers, with rotation, cooldowns after errors and daily limits."""

    def __init__(self, allow_paid: bool = True, order: tuple[str, ...] = PREFERRED_ORDER,
                 slots: tuple[tuple[str, str], ...] = (), task: str = DEFAULT_TASK):
        self.task = task
        self.allow_paid = allow_paid
        self.slots = tuple(name for name, _ in slots) or tuple(order)
        self._lock = threading.Lock()

    @property
    def states(self) -> list[ProviderState]:
        return [_state_for(c) for c in configured_providers() if self.allow_paid or not c.paid]

    def by_name(self, name: str) -> ProviderState | None:
        for state in self.states:
            if state.name == name or state.slot == name:
                return state
        return None

    def _pick(self, slot: str, exclude: set[str]) -> ProviderState | None:
        states = [s for s in self.states if s.name not in exclude and s.slot not in exclude]
        if slot == JUDGE_SLOT:
            candidates = [s for s in states if "judge" in s.config.roles]
        elif slot == AUTO:
            role = "juror" if "writer" in exclude else "writer"
            candidates = [s for s in states if role in s.config.roles]
            if not candidates and role == "juror":
                candidates = [s for s in self.states if "juror" in s.config.roles]
            if candidates:
                with self._lock:
                    start = _rotation[role] % len(candidates)
                    _rotation[role] += 1
                candidates = candidates[start:] + candidates[:start]
        else:
            candidates = [s for s in states if s.name == slot]
        for state in candidates:
            if state.ready and not slot_paused(state.name):
                state.next_allowed_at = max(state.next_allowed_at, time.monotonic() + state.config.minimum_interval)
                return state
        return None

    def wait_for_capacity(self, maximum_wait: float = 180.0) -> bool:
        moments = [s.available_at for s in self.states]
        if not moments:
            return False
        delay = max(0.0, min(moments) - time.monotonic())
        if delay:
            time.sleep(min(delay + 0.2, maximum_wait))
        return any(s.ready for s in self.states)

    def complete(self, system: str, prompt: str, *, max_tokens: int = 1400, temperature: float = 0.0,
                 attempts: int = 4, provider: str = "", wait: bool = True, maximum_wait: float = 180.0,
                 exclude: tuple[str, ...] = ()) -> dict[str, Any]:
        """Calls the first ready provider for the slot and returns its text with the provider name and time."""
        max_tokens = max(int(max_tokens), 512)
        slot = provider or (self.slots[0] if self.slots else AUTO)
        excluded: set[str] = set(exclude)
        errors: list[str] = []
        if not self.states:
            return {"ok": False, "text": "", "provider": "", "errors": ["no model provider is configured"], "paused": False}
        for _ in range(max(1, attempts)):
            state = self._pick(slot, excluded)
            if state is None and wait and not _all_paused(errors) and self.wait_for_capacity(maximum_wait):
                state = self._pick(slot, excluded)
            if state is None:
                break
            if not _count_call(state.name, state.config.daily_limit):
                reason = f"{state.name}:daily-limit of {state.config.daily_limit} calls reached"
                pause_slot(state.name, reason)
                state.exhausted_daily = True
                errors.append(f"{state.slot} paused until midnight: {reason}")
                excluded.add(state.name)
                continue
            started = time.monotonic()
            status, data, detail = provider_complete(state.config, system, prompt, max_tokens, temperature)
            if status == 400 and state.config.kind == "openai":
                # Some endpoints reject strict JSON mode.
                status, data, detail = provider_complete(state.config, system, prompt, max_tokens, temperature, json_mode=False)
            elapsed = time.monotonic() - started
            if status == 200 and isinstance(data, dict):
                text = _content_parse(data)
                if text.strip():
                    with state.lock:
                        state.calls += 1
                        state.total_seconds += elapsed
                        state.last_error = ""
                    return {"ok": True, "text": text, "provider": state.name, "model": state.model,
                            "seconds": round(elapsed, 2)}
                detail = "Empty response"
            with state.lock:
                state.failures += 1
                state.last_error = str(status) + ": " + detail[:120]
                if status == 402:
                    state.cooldown_until = time.monotonic() + BALANCE_COOLDOWN_SECONDS
                elif status in (401, 403, 404):
                    state.cooldown_until = time.monotonic() + 3600
                elif status == 429 and _is_daily_quota(detail):
                    state.cooldown_until = time.monotonic() + DAILY_COOLDOWN_SECONDS
                    state.exhausted_daily = True
                elif status == 429:
                    state.cooldown_until = time.monotonic() + COOLDOWN_SECONDS
                else:
                    state.cooldown_until = time.monotonic() + 15
            errors.append(_error_label(state.slot, status, detail))
            excluded.add(state.name)
        return {"ok": False, "text": "", "provider": "", "errors": errors, "paused": _all_paused(errors)}

    # Kept for importers and the model check in Settings.
    def list_models(self, name: str) -> list[str]:
        return []

    def probe_model(self, provider: str, model: str = "", timeout: float = 25.0) -> tuple[bool, str]:
        state = self.by_name(provider)
        if state is None:
            return False, "Not configured"
        status, data, detail = provider_complete(state.config, "Respond with JSON only.", '{"ok": true}', 600, 0.0,
                                                 timeout=timeout)
        if status == 200 and isinstance(data, dict) and _content_parse(data).strip():
            return True, ""
        return False, str(status) + ": " + detail[:90]

    def live_models(self, provider: str, candidates: list[str], maximum: int = 4) -> list[str]:
        ok, _ = self.probe_model(provider)
        return [self.by_name(provider).model] if ok else []

    def verify(self, name: str = "") -> dict[str, Any]:
        return {s.name: {"model": s.model, "replaced": False, "catalogue": 0} for s in self.states if not name or s.name == name}

    def snapshot(self) -> dict[str, Any]:
        states = self.states
        return {"providers": [s.snapshot() for s in states], "ready": sum(1 for s in states if s.ready),
                "total": len(states)}


def gateway_complete(provider: str, model: str, system: str, prompt: str, max_tokens: int, temperature: float,
                     *, task: str = DEFAULT_TASK, json_mode: bool = True, timeout: float = DEFAULT_TIMEOUT,
                     exclude: tuple[str, ...] = ()) -> tuple[int, Any, str]:
    """One call to a named slot (a provider name, ``judge`` or ``auto``), for callers outside the pool."""
    pool = ProviderPool(slots=((provider, model),), task=task)
    state = pool._pick(provider, set(exclude))
    if state is None:
        return 503, None, f"{provider}: no ready provider"
    if not _count_call(state.name, state.config.daily_limit):
        return 429, None, f"{state.name}:daily-limit reached"
    status, data, detail = provider_complete(state.config, system, prompt, max_tokens, temperature,
                                             json_mode=json_mode, timeout=timeout)
    if isinstance(data, dict):
        data["provider"] = {"provider": state.name, "model": state.model}
    return status, data, detail


def request_replacement(task: str, provider: str, model: str, reason: str) -> bool:
    """No gateway here: a failing provider is reported in Settings instead."""
    return False


def send_feedback(task: str, provider: str, model: str, verdict: str, reason: str) -> bool:
    return False


def web_lookup(domain: str) -> str:
    """Web search for a domain's purpose is not available in this edition; the review goes on without it."""
    return ""


_JSON_BLOCK = re.compile(r"```(?:json)?\s*(.*?)```", re.S)


def extract_json(text: str) -> Any:
    """Extracts JSON from model output that may be wrapped in fences or surrounded by text."""
    clean = str(text or "").strip()
    if not clean:
        return None
    fenced = _JSON_BLOCK.search(clean)
    if fenced:
        clean = fenced.group(1).strip()
    try:
        return json.loads(clean)
    except ValueError:
        pass
    for opener, closer in (("[", "]"), ("{", "}")):
        start = clean.find(opener)
        end = clean.rfind(closer)
        if start != -1 and end > start:
            try:
                return json.loads(clean[start: end + 1])
            except ValueError:
                continue
    return None


if __name__ == "__main__":
    pool = ProviderPool()
    print("Config:", CONFIG_PATH)
    for state in pool.states:
        ok, why = pool.probe_model(state.name)
        print(f"  {state.name:16} {state.model:36} {'ok' if ok else 'failed ' + why}")
