"""Privacy Protector tray icon while the engine runs in the background.

It lives in the engine process itself and appears and disappears with it. Clicking it opens the
dashboard. It has no button to stop the engine, because stopping it cuts DNS for a linked phone.

The traffic light's color is the app's state, explained in the icon tooltip:
  - Red: something needs you: corrupted data, stopped classification, a model verdict the judge could
    not settle, or a red Windows Defender fault.
  - Green: the optional review is deciding on domains right now; it stays green a few seconds after.
  - Orange: the review's providers reached their daily limit, so verdicts wait until midnight.
  - Yellow: a minor note, such as an unlinked phone or a capability that is not watched.
  - White: nothing worth mentioning.
Red overrides green, so green never says "all clear" while a problem exists.

When a judge model is configured it reviews new red and yellow states once (`color_judge.py`): it
approves, lowers or raises them, and until it answers the code's color stands. Safety alerts are
decided by code alone.

Next to it, a mail envelope appears while there is unread checked mail (only when Outlook checking is
on): light brown for mail worth reading, white for ads. Dangerous mail is removed. Clicking it opens
the inbox in Outlook.
"""

from __future__ import annotations

import ctypes
import importlib.util
import json
import logging
import os
import subprocess
import threading
import time
import urllib.request
from pathlib import Path
import hidden_window
import paths

APP_ROOT = Path(__file__).resolve().parent
TRAY_SIZE = 64
_DASHBOARD = {"url": "http://127.0.0.1:8733/"}
TITLE = "Privacy Protector — Running in background"
COLORS = {
    "white": (255, 255, 255),
    "yellow": (255, 214, 10),
    "orange": (255, 149, 0),
    "red": (255, 59, 48),
    "green": (52, 199, 89),
}
# Mail envelope: light brown is close to the Outlook envelope and draws attention to mail worth reading; white does not.
MAIL_COLORS = {"tan": (222, 184, 108), "white": COLORS["white"]}
MAIL_TITLE = "New Mail"
ASSESS_EVERY = 120  # seconds between status checks
FIRST_ASSESS_AFTER = 90  # engine startup grace period before first check
GREEN_HOLD = 4  # seconds green remains after judge approval
TIP_LIMIT = 127  # Windows limit for tray icon tooltip text


def open_dashboard() -> None:
    """Opens the dashboard in the default browser."""
    import webbrowser

    webbrowser.open(_DASHBOARD["url"])


def traffic_icon(size: int = TRAY_SIZE, color: str = "white"):
    """Tray icon: A standing traffic light with a white frame.

    The entire icon, frame and three lights, takes the status color. It is drawn at sixteen times its size then downscaled to keep edges smooth.
    """
    from PIL import Image, ImageDraw

    big = size * 16
    unit = big / 48
    image = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((11.5 * unit, 0.5 * unit, 36.5 * unit, 47.5 * unit), radius=8 * unit,
                           outline=(*COLORS[color], 255), width=round(3 * unit))
    for index in range(3):
        cy, r = (10 + index * 14) * unit, 5.5 * unit
        draw.ellipse((24 * unit - r, cy - r, 24 * unit + r, cy + r), fill=(*COLORS[color], 255))
    return image.resize((size, size), Image.LANCZOS)
def envelope_icon(size: int = TRAY_SIZE, color: str = "tan"):
    """Closed envelope in a single color, with transparent cut-out flap lines. Drawn large then downscaled for smooth edges."""
    from PIL import Image, ImageDraw

    big = size * 16
    mask = Image.new("L", (big, big), 0)
    draw = ImageDraw.Draw(mask)
    left, top, right, bottom = 0.04 * big, 0.2 * big, 0.96 * big, 0.8 * big
    draw.rounded_rectangle((left, top, right, bottom), radius=0.07 * big, fill=255)
    line = int(0.06 * big)
    inset = 0.1 * big
    draw.line(((left + inset, top + inset), (big / 2, 0.55 * big), (right - inset, top + inset)), fill=0, width=line, joint="curve")
    image = Image.new("RGBA", (big, big), (*MAIL_COLORS[color], 255))
    image.putalpha(mask)
    return image.resize((size, size), Image.LANCZOS)


_lock = threading.Lock()
_icon = None
_images: dict = {}
_state = {"level": "white", "reason": "", "deciding": 0, "green_until": 0.0}
_health = None
_wake = threading.Event()


def assess(api: str) -> tuple[str, str]:
    """Current app status: (color, reason). Any failed check is skipped and does not affect others."""
    red: list[str] = []
    yellow: list[str] = []
    safety: set[str] = set()   # Safety alerts: code-only, not judged by the judge (color_judge)
    try:
        # Items the judge could not settle need you. This is the judge's own verdict, so it is not shown
        # to it again (safety). Waiting for the judge colors nothing.
        import ai_reviewer

        notes = ai_reviewer.session_notes()
        if notes:
            title = f"Undecided by the judge: {len(notes)}"
            red.append(title)
            safety.add(title)
    except Exception as error:  # noqa: BLE001
        logging.debug("tray: judge notes failed: %s", error)
    try:
        import health_checks as health

        if health.check_data():
            red.append("Corrupted protection data")
            safety.add("Corrupted protection data")
        # A transient failure colors nothing: right after a restart the checks may fail briefly. Classification
        # counts as stopped only after two consecutive failed checks (ASSESS_EVERY).
        stalled = bool(health.check_classification(api))
        if stalled and _state.get("classification_failed"):
            red.append("Domain classification stopped")
        _state["classification_failed"] = stalled
        if health.check_capabilities(api):
            yellow.append("Incomplete permission monitoring")
    except Exception as error:  # noqa: BLE001
        logging.debug("tray: health checks failed: %s", error)
    try:
        with urllib.request.urlopen(api + "/api/status", timeout=10) as reply:
            reminder = (json.loads(reply.read().decode("utf-8")).get("connectionReminder") or {}).get("state")
        if reminder in ("disconnected", "lost"):
            yellow.append("Phone not connected")
    except Exception as error:  # noqa: BLE001
        logging.debug("tray: status read failed: %s", error)
    try:
        # Defender: protection faults are red, items needing user review are yellow. Dangerous mail is removed
        # silently, so it does not color the indicator.
        with urllib.request.urlopen(api + "/api/pc/security", timeout=10) as reply:
            security = json.loads(reply.read().decode("utf-8"))
        for issue in (security.get("defender") or {}).get("issues") or []:
            (red if issue.get("level") == "red" else yellow).append(issue.get("title", "Defender"))
            if issue.get("level") == "red":
                safety.add(issue.get("title", "Defender"))
    except Exception as error:  # noqa: BLE001
        logging.debug("tray: security read failed: %s", error)
    try:
        with urllib.request.urlopen(api + "/api/settings", timeout=10) as reply:
            chosen = json.loads(reply.read().decode("utf-8")).get("settings") or {}
        if chosen.get("pc"):
            with urllib.request.urlopen(api + "/api/pc/status", timeout=10) as reply:
                routing = json.loads(reply.read().decode("utf-8")).get("routing") or {}
            bypass = routing.get("routed") is False   # None: the check failed, which isn't bypassing
            if bypass and _state.get("bypass_seen"):
                red.append("The PC bypasses the engine")
                safety.add("The PC bypasses the engine")
            _state["bypass_seen"] = bypass
    except Exception as error:  # noqa: BLE001
        logging.debug("tray: routing read failed: %s", error)
    capped: list[str] = []
    try:
        from review_memory import ReviewMemory

        memory = ReviewMemory(paths.DATA_ROOT / "review-memory.json")
        capped = memory.capped()
        waiting = waiting_since(memory.capped_since()) if capped else 0
        if waiting:
            # Model verdicts are paused, so not shown to the judge: code-only (safety)
            title = f"New domains without verdict and models at cap: {waiting}"
            red.append(title)
            safety.add(title)
    except Exception as error:  # noqa: BLE001
        logging.debug("tray: daily caps failed: %s", error)
    red, yellow = judged(red, yellow, safety)
    if red:
        return "red", "Needs you: " + ", ".join(red + yellow)
    if capped:
        return "orange", "Reached daily cap: " + " and ".join(capped) + "".join(", " + t for t in yellow)
    if yellow:
        return "yellow", "Note: " + ", ".join(yellow)
    return "white", ""
def waiting_since(since: float) -> int:
    """Domains with a preliminary verdict from the court since `since` not yet ratified by the judge, on both devices."""
    from datetime import datetime

    count = 0
    for name, field in (("domain-classifications.json", "aiVerdict"), ("pc/domains.json", "verdict")):
        try:
            domains = json.loads((paths.DATA_ROOT / name).read_text(encoding="utf-8")).get("domains") or {}
        except (OSError, ValueError, AttributeError):
            continue
        for entry in domains.values():
            verdict = entry.get(field) if isinstance(entry, dict) else None
            if not isinstance(verdict, dict) or not verdict.get("pendingSonnet"):
                continue
            try:
                stamp = verdict.get("pendingAt") or verdict.get("juryAt") or verdict.get("reviewedAt")
                if datetime.fromisoformat(str(stamp)).timestamp() >= since:
                    count += 1
            except ValueError:
                pass
    return count


def judged(red: list[str], yellow: list[str], safety: set[str] = frozenset()) -> tuple[list[str], list[str]]:
    """The judge model reviews each new red or yellow state before the light is colored (color_judge): what it lowers
    drops, what it raises becomes red, and what is not judged yet keeps the code's color. The query runs in its own
    thread, so the icon never waits for it."""
    try:
        import color_judge

        items = [{"key": color_judge.key_of("tray", t), "sev": sev, "title": t, "safety": t in safety}
                 for sev, group in (("red", red), ("yellow", yellow)) for t in group]
        verdicts = color_judge.review(items)
    except Exception as error:  # noqa: BLE001 - Judge failure keeps the code color
        logging.debug("tray: color judge failed: %s", error)
        return red, yellow
    out: dict[str, list[str]] = {"red": [], "yellow": []}
    for item in items:
        sev = (verdicts.get(item["key"]) or {}).get("sev", item["sev"])
        if sev in out:
            out[sev].append(item["title"])
    return out["red"], out["yellow"]


def _paint() -> None:
    with _lock:
        icon = _icon
        green = _state["deciding"] > 0 or time.time() < _state["green_until"]
        level, reason = _state["level"], _state["reason"]
    if level != "red" and green:
        level, reason = "green", "The review is deciding on domains now"
    if icon is None:
        return
    try:
        if level not in _images:
            _images[level] = traffic_icon(color=level)
        icon.icon = _images[level]
        icon.title = (TITLE + (" — " + reason if reason else ""))[:TIP_LIMIT]
    except Exception as error:  # noqa: BLE001 - Color change does not crash the engine
        logging.debug("tray: repaint failed: %s", error)


def decision_started() -> None:
    """Court session starts: the icon is green while the jury and judge are ruling."""
    with _lock:
        _state["deciding"] += 1
    _paint()


def decision_finished(decided: bool) -> None:
    """Court session ends: if the judge ruled, keep green for a few seconds to be seen, then revert to the status color."""
    with _lock:
        _state["deciding"] = max(0, _state["deciding"] - 1)
        if decided:
            _state["green_until"] = time.time() + GREEN_HOLD
    _paint()
    if decided:
        timer = threading.Timer(GREEN_HOLD + 0.2, _paint)
        timer.daemon = True
        timer.start()


def _watch(api: str) -> None:
    time.sleep(FIRST_ASSESS_AFTER)
    while True:
        level, reason = assess(api)
        with _lock:
            _state["level"], _state["reason"] = level, reason
        _paint()
        _wake.wait(ASSESS_EVERY)
        _wake.clear()
def poke(after: float = 5.0) -> None:
    """Re-check status after seconds, not minutes: provisional verdict during daily limit is saved then turns red immediately."""
    timer = threading.Timer(after, _wake.set)
    timer.daemon = True
    timer.start()


def start(api: str = "http://127.0.0.1:8733") -> object | None:
    _DASHBOARD["url"] = api + "/"
    """Shows the icon in a separate thread, and returns it so the engine can hide it on shutdown.

    Failure here does not stop the engine: protection is more important than the icon.
    """
    try:
        import pystray
        import PIL  # noqa: F401 - drawing needs it
    except ImportError as error:
        logging.warning("Tray icon unavailable: %s", error)
        return None
    try:
        image = traffic_icon()
        menu = pystray.Menu(
            pystray.MenuItem("Open Privacy Protector", lambda icon, item: open_dashboard(), default=True),
        )
        icon = _icon_with_guid(pystray, KEY_ICON_GUID)("privacy-protector", image, TITLE, menu)
    except Exception as error:  # noqa: BLE001 - icon does not crash the engine
        logging.warning("Failed to create tray icon: %s", error)
        return None
    global _icon
    with _lock:
        _icon = icon
    _images["white"] = image
    threading.Thread(target=icon.run, name="tray-icon", daemon=True).start()
    threading.Thread(target=_watch, args=(api,), name="tray-status", daemon=True).start()
    return icon


_mail = {"icon": None, "level": None, "tip": ""}
_mail_images: dict = {}


def _apply_mail() -> None:
    icon, level, tip = _mail["icon"], _mail["level"], _mail["tip"]
    if icon is None:
        return
    try:
        if level:
            if level not in _mail_images:
                _mail_images[level] = envelope_icon(color=level)
            icon.icon = _mail_images[level]
            icon.title = (MAIL_TITLE + (" — " + tip if tip else ""))[:TIP_LIMIT]
        icon.visible = bool(level)
    except Exception as error:  # noqa: BLE001 - envelope does not crash the engine
        logging.debug("tray: mail badge failed: %s", error)


def mail_badge(level: str | None, tip: str = "") -> None:
    """Shows the envelope with its color (tan or white) or hides it (None). Called from the mail thread."""
    with _lock:
        _mail["level"], _mail["tip"] = level, tip
    _apply_mail()


# Identity of each icon on Windows. Windows saves icon position by program
# and its number, and all user apps in Python run under the same pythonw.exe; pystray sends `hID` instead of `uID`
# so the number always arrives as 0. Thus attach the envelope to the key, then with number 1 attach to WiFi Talk icon.
# A fixed GUID that does not repeat.
KEY_ICON_GUID = "6e721b52-7610-43a5-8ecf-7ee4c4f4c632"
MAIL_ICON_GUID = "6860888b-c93c-44ed-bb33-6ccff841001b"
NIF_GUID = 0x20
NIM_ADD, NIM_DELETE = 0, 2


def _icon_with_guid(pystray, guid: str):
    """pystray icon with its own GUID identity, so Windows does not link it to another icon."""
    import uuid

    base = pystray.Icon
    if not hasattr(base, "_message"):
        return base  # non-Windows
    raw = uuid.UUID(guid)

    class Icon(base):
        def _message(self, code, flags, **kwargs):
            from pystray._util import win32

            value = win32.NOTIFYICONDATAW.GUID(raw.time_low, raw.time_mid, raw.time_hi_version,
                                               (ctypes.c_ubyte * 8)(*raw.bytes[8:]))

            def send(message, message_flags, **extra):
                if getattr(self, "_no_guid", False):
                    identity = {"uID": 1 if guid == MAIL_ICON_GUID else 0}
                else:
                    identity = {"uFlags": message_flags | NIF_GUID, "guidItem": value}
                return win32.Shell_NotifyIcon(message, win32.NOTIFYICONDATAW(
                    cbSize=ctypes.sizeof(win32.NOTIFYICONDATAW), hWnd=self._hwnd,
                    **{"uFlags": message_flags, **identity}, **extra))

            if code == NIM_ADD and not getattr(self, "_no_guid", False):
                # Icon remaining from a previous process that ended abruptly prevents adding the same GUID, so delete first.
                send(NIM_DELETE, 0)
            if not send(code, flags, **kwargs) and code == NIM_ADD and not getattr(self, "_no_guid", False):
                # Windows rejected the GUID because it was registered for another program path: add icon by number.
                self._no_guid = True
                send(code, flags, **kwargs)

    return Icon
def start_mail(on_click) -> object | None:
    """Mail envelope: a secondary icon in the engine process, hidden until an unread message arrives."""
    try:
        import pystray
    except ImportError:
        return None

    def clicked(icon, item):
        try:
            import ctypes

            ctypes.windll.user32.AllowSetForegroundWindow(-1)  # Let Outlook come forward on user click
        except Exception:  # noqa: BLE001
            pass
        on_click()

    def setup(icon):
        with _lock:
            _mail["icon"] = icon
        _apply_mail()

    try:
        icon = _icon_with_guid(pystray, MAIL_ICON_GUID)("privacy-protector-mail", envelope_icon(), MAIL_TITLE,
                            pystray.Menu(pystray.MenuItem("Open Inbox", clicked, default=True)))
    except Exception as error:  # noqa: BLE001
        logging.warning("Failed to create mail envelope: %s", error)
        return None
    threading.Thread(target=icon.run, kwargs={"setup": setup}, name="tray-mail", daemon=True).start()
    return icon


def stop(icon: object | None) -> None:
    for each in (icon, _mail["icon"]):
        if each is None:
            continue
        try:
            each.stop()
        except Exception:  # noqa: BLE001
            pass
