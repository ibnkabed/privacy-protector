"""Judging a capability use: three separate verdicts with fixed rules, no model.

1. Role: does the capability have a legitimate role in this program?
2. Cause: what is the evidence for the cause of this specific event?
3. Action: what is possible now, and who holds it?

Each has "undetermined" with a reason and a step to complete. The program name, path and command
line are data matched by fixed patterns, never read as instructions. Identity is by path and
package, not by name alone: QtWebEngineProcess inside iAnyGo is not its counterpart inside Plex.

The summary for display has four values:
- allow: conditional allowance based on the user's request and the program's identity; not a
  certification that the event is safe.
- monitor: a plausible role the data is not enough to settle.
- deny: a provisional denial of the capability for lack of a specific need; not a finding of spying.
- undetermined: a program or endpoint with no rule; it does not turn into an allowance.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import user_exceptions
import paths

RULES_VERSION = 1
FOCUS_CAPABILITIES = ("microphone", "webcam", "location", "contacts")

VERDICT_LABELS = {
    "allow": "conditional allow",
    "monitor": "monitor",
    "deny": "provisional capability denial",
    "undetermined": "undetermined",
}

INTERPRETERS = re.compile(r"^(python|pythonw|py|node|bun|deno|pwsh|powershell|wscript|cscript|java|javaw)\.exe$", re.I)
SHARED_HOSTS = re.compile(r"^(svchost|dllhost|rundll32|runtimebroker|backgroundtaskhost|taskhostw|wmiprvse)\.exe$", re.I)
BROWSERS = re.compile(r"^(chrome|msedge|firefox|brave|opera|vivaldi|arc)\.exe$", re.I)
def is_trusted_program(path: str) -> bool:
    """A program inside a folder you trusted in Settings."""
    return bool(user_exceptions.program_allowed(path))


@dataclass
class Rule:
    """A rule: if the identity and the capability match, these are its verdicts."""

    id: str
    capabilities: tuple[str, ...]
    verdict: str
    role: str
    cause: str
    action: str
    path: re.Pattern[str] | None = None
    name: re.Pattern[str] | None = None
    package: re.Pattern[str] | None = None
    role_state: str = "justified"
    sources: tuple[str, ...] = field(default_factory=tuple)

    def matches(self, capability: str, identity: dict[str, Any]) -> bool:
        if self.capabilities and capability not in self.capabilities:
            return False
        if self.package is not None:
            return bool(identity.get("package")) and bool(self.package.search(identity["package"]))
        if self.path is not None:
            return bool(self.path.search(identity.get("path") or ""))
        if self.name is not None:
            return bool(self.name.search(identity.get("name") or ""))
        return False


def _r(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.I)
MIC = ("microphone",)
LOC = ("location",)
VOICE_ACTION = "Allowed for a voice session you start; if use you did not start appears, block it from the block button"

RULES: tuple[Rule, ...] = (
    # -- Precautionary block: no documented need for precise location ----------
    Rule("plex-location", LOC, "deny", path=_r(r"\\plex\\"),
         role="Media playback does not need precise location, and no documented function justifies it",
         cause="The cause of the event is unknown; approximate location in the company's policy does not prove this request is promotional",
         action="Block location for this program unless a feature you requested that needs it appears", role_state="not-justified"),
    Rule("ea-location", LOC, "deny", path=_r(r"\\electronic arts\\|eacefsubprocess\.exe$|\\ea desktop\\"),
         role="Running and downloading games does not need precise location",
         cause="The cause of the event is unknown; EA's policy declares approximate location and advertising, which does not prove this request is promotional",
         action="Block location for this program, without blocking the EA connections games need", role_state="not-justified"),
    Rule("chatgpt-location", LOC, "deny", name=_r(r"^chatgpt\.exe$"),
         role="Text and voice chat do not need precise location",
         cause="The cause of the event is unknown, and there is no evidence of a promotional cause",
         action="Block location until a feature you requested that needs it appears", role_state="not-justified"),
    # -- Phone location-changing tools: PC location is not required for their function
    Rule("phone-location-tools", LOC, "monitor",
         path=_r(r"\\(tenorshare )?ianygo\\|\\anygo\\|\\mocpogo\\|anygow\.exe$|mocpogow\.exe$"),
         role="Their function is changing the phone's location; the PC's real location is only needed for the 'locate me' feature on the map",
         cause="The log does not show whether you used that feature", role_state="plausible",
         action="Allowed only for the map feature; if it recurs without your use, block it"),
    # -- Security software: Wi-Fi and VPN pass through interfaces that require location permission
    Rule("norton-location", LOC, "monitor", path=_r(r"\\norton\\"),
         role="Assessing Wi-Fi networks and automatic VPN connection pass through interfaces that Windows ties to location permission",
         cause="No documentation links these events to that function, and the log does not prove coordinates were sent", role_state="plausible",
         action="Blocking it may stop automatic VPN connection on untrusted networks; the decision is yours"),
    Rule("netsh-location", LOC, "allow", name=_r(r"^netsh\.exe$"),
         role="Listing nearby Wi-Fi networks requires location permission in Windows",
         cause="The command that ran is not recorded, so it does not prove coordinates were sent",
         action="No action; it is a system tool that you or your programs run"),
    Rule("dashost-location", LOC, "monitor", name=_r(r"^dashost\.exe$"),
         role="Windows device association host; it may need location to discover wireless devices", role_state="plausible",
         cause="The log does not show the device or the purpose",
         action="A system component is not blocked wholesale"),
    # -- Windows packages -------------------------------------------------------
    Rule("screensketch-mic", MIC, "allow", package=_r(r"^microsoft\.screensketch_"),
         role="Snipping Tool records the screen with a voice annotation",
         cause="The recording duration does not prove the recording is the cause", action="Allowed when screen recording starts"),
    Rule("soundrecorder-mic", MIC, "allow", package=_r(r"^microsoft\.windowssoundrecorder_"),
         role="Windows Sound Recorder: recording with the microphone is its function",
         cause="The event is a recording session you opened", action="No action"),
    Rule("intel-sur-location", LOC, "deny", path=_r(r"\\intel\\sur\\|esrv_svc\.exe$"),
         role="Intel System Usage Report service collects device usage statistics, and location is not part of its function",
         cause="No function visible to the user explains the location request", role_state="not-justified",
         action="Windows does not block location for a specific desktop service; removing Intel Computing Improvement Program ends it"),
    Rule("settings-mic", MIC, "allow", package=_r(r"^windows\.immersivecontrolpanel_"),
         role="Windows Settings tests the microphone by recording a short sample",
         cause="The event's duration does not prove the test is the cause", action="No action"),
    Rule("settings-location", LOC, "monitor", package=_r(r"^windows\.immersivecontrolpanel_"),
         role="Windows Settings may read location while its settings page is open", role_state="plausible",
         cause="The log does not identify the page or the purpose", action="A system component is not blocked wholesale"),
    Rule("input-mic", MIC, "allow", package=_r(r"^microsoftwindows\.client\.cbs_"),
         role="The input package (TextInputHost) declares the microphone for voice dictation",
         cause="The package includes other components, so it does not prove dictation is the cause", action="Allowed for dictation you start"),
    Rule("shell-contacts", ("contacts",), "monitor", package=_r(r"^microsoft\.windows\.shellexperiencehost_"),
         role="The Windows shell experience host declares contactsSystem in its manifest", role_state="plausible",
         cause="The manifest does not show the reason for reading, the number of contacts, or where they go", action="Monitor the purpose"),
    Rule("passkeys", ("passkeys", "passkeysEnumeration"), "allow", name=_r(r".*"),
         role="Passkeys are displayed when you start a sign-in on a site or app",
         cause="The log does not show the site requested", action="No action"),
    # -- Voice tools used by the user --------------------------------------------
    Rule("claude-voice", MIC, "allow", package=_r(r"^claude_"),
         role="Voice chat and dictation in Claude", cause="The log does not prove you started every session", action=VOICE_ACTION),
    Rule("claude-voice-exe", MIC, "allow", name=_r(r"^claude\.exe$"),
         role="Voice chat and dictation in Claude", cause="The log does not prove you started every session", action=VOICE_ACTION),
    Rule("codex-voice", MIC, "allow", package=_r(r"^openai\.codex_"),
         role="Voice input in Codex", cause="The log does not prove you started every session", action=VOICE_ACTION),
    Rule("codex-voice-exe", MIC, "allow", name=_r(r"^codex\.exe$"),
         role="Voice input in Codex", cause="The log does not prove you started every session", action=VOICE_ACTION),
    Rule("cursor-voice", MIC, "allow", name=_r(r"^cursor\.exe$"),
         role="Dictation from the microphone button in Cursor", cause="The log does not prove you started every session", action=VOICE_ACTION),
    Rule("devin-voice", MIC, "allow", name=_r(r"^devin\.exe$"),
         role="Voice calls in Devin", cause="The log does not prove you started every session", action=VOICE_ACTION),
    Rule("codex-computer-use", ("graphicsCaptureWithoutBorder", "graphicsCaptureProgrammatic", "screenCapture"), "allow",
         name=_r(r"^codex-computer-use(-swift)?\.exe$"),
         role="The computer control tool in Codex captures the screen in order to operate", cause="It works when you request a task from it", action="No action"),
    Rule("screensketch-capture", ("graphicsCaptureWithoutBorder", "graphicsCaptureProgrammatic", "screenCapture"), "allow",
         package=_r(r"^microsoft\.screensketch_"),
         role="Snipping Tool captures the screen when you request a screenshot or recording", cause="The log does not show whether you requested the capture", action="No action"),
    Rule("onenote-capture", ("graphicsCaptureWithoutBorder", "graphicsCaptureProgrammatic", "screenCapture"), "allow",
         name=_r(r"^onenote\.exe$"),
         role="Screen clipping in OneNote", cause="The log does not show whether you clipped the screen", action="No action"),
)


def _browser_judgment(capability: str) -> dict[str, Any] | None:
    if capability not in ("microphone", "webcam", "location"):
        return None
    return {
        "rule": "browser",
        "verdict": "allow",
        "role": {"state": "justified", "text": "The browser passes the permission to a website that requests it and the user grants it"},
        "cause": {"state": "undetermined", "text": "The requesting website is unknown: Windows does not record it",
                  "next": "Review site permissions in your browser settings, and allow only the sites you need"},
        "action": {"state": "browser", "text": "Control per site from the browser's settings, not from Windows"},
    }
def _interpreter_judgment(capability: str, identity: dict[str, Any]) -> dict[str, Any]:
    script = str(identity.get("script") or "")
    name = identity.get("name") or ""
    if script and user_exceptions.program_allowed(script):
        return {
            "rule": "trusted-script",
            "verdict": "allow",
            "role": {"state": "justified", "text": f"Script from a folder you trust, run by {name}"},
            "cause": {"state": "established", "text": "The script is known from the process command line at the time of use"},
            "action": {"state": "none", "text": "No action; if you did not run it, review the script"},
        }
    if script:
        return {
            "rule": "interpreter-script",
            "verdict": "monitor",
            "role": {"state": "plausible", "text": f"{name} is running a script from outside your projects"},
            "cause": {"state": "established", "text": "The script is known from the process command line"},
            "action": {"state": "review", "text": "Review the script; denying the permission to the runner blocks it for all of its scripts"},
        }
    return {
        "rule": "interpreter-unknown",
        # Monitoring decision as a shared-system host: the runner is neither blocked
        # outright nor granted blanket permission, and the live monitor judges the script once it is known.
        # "Undetermined" used to leave the planet without a verdict.
        "verdict": "monitor",
        "role": {"state": "undetermined", "text": f"{name} runs different scripts, not a single program"},
        "cause": {"state": "undetermined", "text": "The script is unknown: the Windows log does not record it",
                  "next": "The live monitor saves the script for the microphone from now on; for other permissions it remains unknown"},
        "action": {"state": "review", "text": "The runner is not granted blanket permission nor blocked outright before its script is known"},
    }


def _shared_host_judgment(identity: dict[str, Any]) -> dict[str, Any]:
    name = identity.get("name") or ""
    service = identity.get("service") or ""
    return {
        "rule": "shared-host",
        "verdict": "monitor",
        "role": {"state": "undetermined",
                 "text": f"{name} is a host that acts on behalf of other programs or services" + (f" (service: {service})" if service else "")},
        "cause": {"state": "undetermined", "text": "The log does not state which component requested the permission",
                  "next": "No available source reveals the component without higher privileges"},
        "action": {"state": "none", "text": "A system host is not blocked outright; blocking it blocks everything it hosts"},
    }


USER_DECISIONS_PATH = paths.PC_ROOT / "capability-user-decisions.json"
_user_cache: dict[str, Any] = {"mtime": None, "rows": []}


def user_decision(capability: str, path: str) -> dict[str, Any] | None:
    """Your decision on a program's permission by its folder, covering all its copies.

    It precedes all the rules: it is the decisive verdict on what Windows cannot enforce, so the planet is never left without a verdict."""
    try:
        mtime = USER_DECISIONS_PATH.stat().st_mtime
    except OSError:
        return None
    if _user_cache["mtime"] != mtime:
        try:
            rows = json.loads(USER_DECISIONS_PATH.read_text(encoding="utf-8")).get("decisions") or []
        except (OSError, ValueError):
            rows = []
        _user_cache.update(mtime=mtime, rows=[row for row in rows if isinstance(row, dict)])
    clean = path.lower().rstrip("\\")
    for row in _user_cache["rows"]:
        folder = str(row.get("folder") or "").lower().rstrip("\\")
        if row.get("capability") == capability and folder and (clean == folder or clean.startswith(folder + "\\")):
            return row
    return None


def judge(capability: str, identity: dict[str, Any]) -> dict[str, Any]:
    """The three verdicts and their summary, including the effect of file state and identity change."""
    name = str(identity.get("name") or "")
    result: dict[str, Any] | None = None
    path = str(identity.get("path") or "")
    if is_trusted_program(path):
        result = {
            "rule": "trusted-program",
            "verdict": "allow",
            "role": {"state": "justified", "text": f"{name} is in a folder you trust"},
            "cause": {"state": "established", "text": "The program path is inside a folder you trusted in Settings"},
            "action": {"state": "none", "text": "No action; full allowance for programs you trust"},
        }
    for rule in RULES if result is None else ():
        if rule.matches(capability, identity):
            result = {
                "rule": rule.id,
                "verdict": rule.verdict,
                "role": {"state": rule.role_state, "text": rule.role},
                "cause": {"state": "undetermined", "text": rule.cause},
                "action": {"state": "recommend-deny" if rule.verdict == "deny" else ("monitor" if rule.verdict == "monitor" else "none"),
                           "text": rule.action},
            }
            break
    if result is None and BROWSERS.search(name):
        result = _browser_judgment(capability)
    if result is None and INTERPRETERS.search(name):
        result = _interpreter_judgment(capability, identity)
    if result is None and SHARED_HOSTS.search(name):
        result = _shared_host_judgment(identity)
    if result is None:
        result = {
            "rule": "none",
            "verdict": "undetermined",
            "role": {"state": "undetermined", "text": "No rule for this program with this permission"},
            "cause": {"state": "undetermined", "text": "No evidence of the cause of the event",
                      "next": "A rule is added after studying the program and its function; until then it does not count as allowance"},
            "action": {"state": "review", "text": "Review the program; you can block the permission for it from the block button"},
        }
    decided = user_decision(capability, path) if path else None
    if decided and decided.get("verdict") in VERDICT_LABELS:
        result = {
            "rule": "user-decision",
            "verdict": decided["verdict"],
            "role": result["role"],
            "cause": result["cause"],
            "action": {"state": "user", "text": f"Your decision on {decided.get('at', '')}: " + str(decided.get("reason") or "")},
            "ruleVerdict": result["verdict"],
        }
    notes: list[str] = []
    file_state = identity.get("fileState") or ""
    if file_state == "missing":
        notes.append("The file no longer exists: no identity from today is attached to it, and no copy that once existed is established")
        result["cause"] = {**result["cause"], "state": "undetermined"}
    elif file_state == "changed-after":
        notes.append("The file changed after the event: its current identity does not concern the event")
    if identity.get("identityChanged"):
        notes.append("The program identity (version or fingerprint) changed since an earlier decision; the permission is shown to you again and is not withdrawn automatically")
    if identity.get("signature") == "invalid":
        notes.append("The file signature is invalid")
        if result["verdict"] == "allow":
            result["verdict"] = "monitor"
    result["notes"] = notes
    result["label"] = VERDICT_LABELS[result["verdict"]]
    result["rulesVersion"] = RULES_VERSION
    return result
