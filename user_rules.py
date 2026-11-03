"""Owner rules: binding rulings that a cloud model cannot override.

The models judge and vote, and these rules are the guide that sets their limits. They have two jobs:
- `rules_prompt()` writes them for the models before judging, so they know the limits from the first request.
- `enforce()` applies them after judging and voting; if a verdict violates them, it is corrected even if all
  models agreed, and the rule name that corrected it is recorded in the verdict.

All are extracted from the user's previous decisions: blocking must not break the app, health and fitness
data is a service for its owner, attendance location at check-in time is a function and location rights belong
only to those whose function is location, downloading maps
and content is a feature for the device owner, infrastructure and protection services are not blocked, doubt
does not justify blocking, and the user's manual decision is untouched by a model. Every new rule enacted
is added here.
"""

from __future__ import annotations

import re
from typing import Any

from domain_verdicts import (
    _NEVER_BLOCK_CATEGORIES,
    _base_domain,
    _first_party_for_caller,
    caller_purpose,
    domain_function_role,
)

# Health and fitness device manufacturers: their domain carrying a health data label is recognized by name alone,
# because the mobile device does not always reveal the calling app.
HEALTH_VENDOR_BASES = frozenset(
    {
        "dbankcloud.com", "dbankcloud.cn", "dbankcloud.eu", "dbankcloud.asia",
        "hicloud.com", "myhuaweicloud.com", "huawei.com",
        "samsunghealth.com", "samsung.com", "garmin.com", "garmin.cn", "fitbit.com",
        "zepp.com", "huami.com", "amazfit.com", "mi.com", "polar.com", "suunto.com",
        "withings.com", "apple.com",
    }
)
HEALTH_LABEL = re.compile(
    r"health|sport|fitness|workout|steps?\b|heart|sleep|wearable|activity", re.I
)
ATTENDANCE_HOST = re.compile(r"huduri|hudur|availo|hather|attendance", re.I)
HEALTH_PURPOSE = "Health app"
ATTENDANCE_PURPOSE = "Attendance app"

# Infrastructure and protection service categories: their color is green and they are not blocked.
INFRASTRUCTURE_CATEGORIES = frozenset(
    {"infrastructure", "privacy_protection", "push", "dns_service_discovery", "service_identity"}
)

# Rules in order of application. `color` is the color enforced if the rule matches, and `None` keeps the model's color
# and only prevents blocking. The last two rules are a guide for the models, applied in voting and in automatic
# blocking itself.
RULES: tuple[dict[str, Any], ...] = (
    {
        "id": "health",
        "title": "Health and fitness data belongs to its owner",
        "text": "What a health, fitness, or watch app uploads of steps, heart rate, sleep, and activity to display "
                "for its owner or transfer to another health app is a service for them, not spying on them: "
                "green and not blocked, even if the upload is regular and background, and even if the domain comes "
                "without a known calling app, as long as its name is a health data name at a health device manufacturer.",
        "color": "green",
    },
    {
        "id": "attendance",
        "title": "Attendance location is a function",
        "text": "The purpose of an attendance app is to know your location at check-in time; its domains that handle "
                "check-in and identity are its function: green and not blocked.",
        "color": "green",
    },
    {
        "id": "infrastructure",
        "title": "Infrastructure and protection services",
        "text": "DNS resolvers, push notifications, certificate verification, private relays, and anonymity services: "
                "green and not blocked, because blocking them cuts off service for the device owner.",
        "color": "green",
    },
    {
        "id": "no-break",
        "title": "Do not block what stops app functionality",
        "text": "Do not block a domain that stops the function for which the app was installed: downloading maps and "
                "content for offline use, single sign-on, notification delivery, fraud detection, government services, "
                "the app owner's own domain, and developer tool domains such as mobile location spoofing for testing. "
                "Disabling an app needed by the user is worse than leaving a tracker unblocked; if something breaks, "
                "its blocking is lifted.",
        "color": None,
    },
    {
        "id": "extra-is-blockable",
        "title": "Extras beyond functionality are blocked",
        "text": "Analytics, advertising, attribution, crash reports, marketing messages, and performance monitoring "
                "are extra to the app's function, so they are blocked even if their caller is an app needed by the user. "
                "Red is not generalized to all domains of an app proven to violate: only the violating domain is targeted, "
                "as violation domains are separate from operational domains.",
        "color": None,
        "guide_only": True,
    },
    {
        "id": "location",
        "title": "Location rights belong to those whose function is location",
        "text": "Location requests are a right for apps whose function is location, such as attendance at check-in, maps, "
                "weather, delivery, and health. A banking app, Tawakkalna, government apps, social networks, and games "
                "have no right to request your location or movement, and if the request comes after you disabled the feature, "
                "it is even more severe. The system-shared location domain is not blocked because blocking it breaks attendance "
                "and maps; so the violation is recorded against the requesting app, not the shared domain.",
        "color": None,
        "guide_only": True,
    },
    {
        "id": "doubt",
        "title": "Doubt does not justify blocking",
        "text": "Blocking occurs only for red verdicts that won the majority of votes and where most voters said blocking "
                "is safe; in case of a tie, the lighter option is taken. The user's manual decision is untouched by a model.",
        "color": None,
        "guide_only": True,
    },
)
_BY_ID = {rule["id"]: rule for rule in RULES}


def rules_prompt() -> str:
    """Rules as text for the models: appended to the verdict standard in every request."""
    lines = ["The user's binding rules — do not violate them; if your verdict violates them, it will be corrected:"]
    lines += ["- " + rule["title"] + ": " + rule["text"] for rule in RULES]
    return "\n".join(lines)


def _is_health(name: str, callers: tuple[str, ...], category: str) -> bool:
    if category == "expected_health_data":
        return True
    first_label = name.split(".", 1)[0]
    if _base_domain(name) in HEALTH_VENDOR_BASES and HEALTH_LABEL.search(first_label):
        return True
    return bool(callers) and caller_purpose(callers).startswith(HEALTH_PURPOSE) and (
        _first_party_for_caller(name, callers)
    )


def _is_attendance(name: str, callers: tuple[str, ...]) -> bool:
    if ATTENDANCE_HOST.search(name):
        return True
    return bool(callers) and caller_purpose(callers).startswith(ATTENDANCE_PURPOSE) and (
        _first_party_for_caller(name, callers)
    )


def matching_rule(
    domain: str, callers: tuple[str, ...] = (), category: str = ""
) -> tuple[str, str]:
    """First binding rule protecting this domain: (its ID, its reason), or ("", "")."""
    name = str(domain or "").strip().strip(".").lower()
    if not name:
        return "", ""
    callers = tuple(str(item) for item in callers if str(item).strip())
    role, reason = domain_function_role(name, callers)
    if role == "additional":
        # Excess beyond function is not protected by a rule even if called by a health or attendance app.
        return "", ""
    if _is_health(name, callers, category):
        return "health", "Health and fitness data domain for the user"
    if _is_attendance(name, callers):
        return "attendance", "Attendance app domain performing preparation"
    if category in INFRASTRUCTURE_CATEGORIES:
        return "infrastructure", "Its local category is infrastructure or protection service"
    if role == "function":
        return "no-break", reason
    if category in _NEVER_BLOCK_CATEGORIES:
        return "no-break", "Its local category is an operational path"
    return "", ""


def enforce(
    domain: str, verdict: dict[str, Any], callers: tuple[str, ...] = (), category: str = ""
) -> dict[str, Any]:
    """Corrects the models' verdict using the user's rules, and records the rule that corrected it."""
    rule_id, why = matching_rule(domain, callers, category)
    if not rule_id:
        return verdict
    rule = _BY_ID[rule_id]
    before = (verdict.get("color"), bool(verdict.get("blockSafe")))
    if rule["color"]:
        verdict["color"] = rule["color"]
    verdict["blockSafe"] = False
    verdict["ownerRule"] = rule_id
    if (verdict.get("color"), False) != before:
        verdict["reason"] = (
            str(verdict.get("reason", ""))
            + " — and corrected by the protection rule \""
            + rule["title"]
            + "\" ("
            + why
            + ")."
        )
    return verdict
