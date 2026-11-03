"""Reviewed verdict layer for domains — only three colors.

Verdict rules:

* ``red``    — Explicit privacy violation: third-party ad, tracking, attribution, and
               behavioral analytics networks. Any domain present on the device for the
               purpose of collecting user data rather than running the app.
* ``orange`` — Worth monitoring: crash diagnostics, first-party performance measurement,
               device identifiers, operational location, contacts, remote configuration.
               There is no definitive confirmation of a violation.
* ``green``  — Safe and functional: infrastructure, certificates, notifications, maps,
               authentication, app stores, and everything originating from health and
               fitness apps (Apple Health, Huawei Health, and similar) by the user's decision.

Order matters: ``GREEN_OVERRIDES`` is checked first, then ``RED_RULES``, then
``ORANGE_RULES``. Anything no rule matches falls back to the legacy catalog and the
automatic inference in ``domain_classifier``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

VERDICT_RULESET_VERSION = 1


def _verdict(
    risk: str,
    category: str,
    category_label: str,
    summary: str,
    reason: str,
    source: str = "",
    *,
    developer_check: bool = False,
    device_data: bool = False,
) -> dict[str, Any]:
    return {
        "risk": risk,
        "category": category,
        "categoryLabel": category_label,
        "summary": summary,
        "reason": reason,
        "source": source,
        "developerModeCheck": developer_check,
        "deviceDataAccess": device_data,
    }


def _rule(pattern: str, verdict: dict[str, Any]) -> tuple[re.Pattern[str], dict[str, Any]]:
    return (re.compile(pattern, re.I), verdict)


# ---------------------------------------------------------------------------
# Green — highest priority (takes precedence over red and orange rules)
# ---------------------------------------------------------------------------

_HEALTH = _verdict(
    "green",
    "expected_health_data",
    "Expected health and fitness data",
    "A domain serving a health or fitness app; exchanging activity data with it is the app's own function.",
    "User's decision: health and fitness app domains are treated as safe because sending fitness data to them is expected and intended.",
    "https://support.apple.com/en-us/HT203037",
    device_data=True,
)

_APPLE_FUNCTIONAL = _verdict(
    "green",
    "functional_service",
    "Functional service from the device maker",
    "An operational Apple infrastructure endpoint for delivering notifications, device setup, or certificate validation.",
    "A system service that does not collect user behavior; disabling it breaks core device functions.",
    "https://support.apple.com/en-us/101555",
)

_GOOGLE_FUNCTIONAL = _verdict(
    "green",
    "functional_service",
    "Functional service from Google",
    "An operational endpoint for connectivity checks, notification delivery, or component updates.",
    "A known infrastructure service that is not tied to a user's advertising profile.",
    "https://developers.google.com/",
)

_SECURITY_FUNCTIONAL = _verdict(
    "green",
    "privacy_protection",
    "Security verification and protection",
    "A service that verifies certificate or device integrity, or protects against malicious sites.",
    "Designed for protection rather than tracking, and does not transmit a behavioral profile of the user.",
    "https://developer.apple.com/documentation/devicecheck",
)
_CDN_FUNCTIONAL = _verdict(
    "green",
    "infrastructure",
    "content delivery network",
    "Hosting of static files, images and fonts for an app or website.",
    "Content delivery only, with no event collection point or advertising identifier.",
)

GREEN_OVERRIDES: tuple[tuple[re.Pattern[str], dict[str, Any]], ...] = (
    # --- Health and fitness apps ---
    _rule(r"(?:^|\.)health\.apple\.com$", _HEALTH),
    _rule(r"(?:^|\.)fitness\.apple\.com$", _HEALTH),
    _rule(r"^[\w-]*(?:sport|health|fitness|achievement|wellness)[\w-]*-dra\.", _HEALTH),
    _rule(r"^[\w-]*(?:sporthealth|healthkit|fitnesskit)[\w-]*\.", _HEALTH),
    _rule(r"(?:^|\.)myhuaweicloud\.com$", _HEALTH),
    _rule(r"(?:^|\.)hicloud\.com$", _HEALTH),
    _rule(r"(?:^|\.)dbankcloud\.(?:com|cn|eu|asia)$", _HEALTH),
    _rule(r"(?:^|\.)dbankcdn\.(?:com|cn)$", _HEALTH),
    _rule(r"(?:^|\.)cdnhwc\d*\.com$", _HEALTH),
    # --- Security verification ---
    _rule(r"appattest", _SECURITY_FUNCTIONAL),
    _rule(r"(?:^|\.)safebrowsing\.google(?:apis)?\.com$", _SECURITY_FUNCTIONAL),
    _rule(r"^(?:ocsp|crl|status)[\w.-]*\.(?:apple|globalsign|digicert|rapidssl|sectigo|verisign|entrust)\.com$", _SECURITY_FUNCTIONAL),
    _rule(r"(?:^|\.)sdk\.awswaf\.com$", _SECURITY_FUNCTIONAL),
    _rule(r"(?:^|\.)cardinalcommerce\.com$", _SECURITY_FUNCTIONAL),
    # --- Apple notifications and operational infrastructure ---
    _rule(r"(?:^|[.-])push[.-]apple\.com$", _APPLE_FUNCTIONAL),
    _rule(r"(?:^|\.)courier[\w-]*\.push[.-]apple\.com", _APPLE_FUNCTIONAL),
    _rule(r"^\d+-courier\d*\.push\.apple\.com$", _APPLE_FUNCTIONAL),
    _rule(r"(?:^|\.)gc\.apple\.com$", _APPLE_FUNCTIONAL),
    _rule(r"(?:^|\.)gc-apple\.com", _APPLE_FUNCTIONAL),
    _rule(r"(?:^|\.)gc\.fe2\.apple-dns\.net$", _APPLE_FUNCTIONAL),
    _rule(r"(?:^|\.)weatherkit\.apple\.com", _APPLE_FUNCTIONAL),
    _rule(r"^(?:nc-pod\d+-)?smp-device[\w.-]*\.(?:apple\.com|g\.aaplimg\.com)$", _APPLE_FUNCTIONAL),
    _rule(r"^(?:ma-)?sq-device\.apple\.com$", _APPLE_FUNCTIONAL),
    _rule(r"[\w-]*wpc-device\.apple\.com$", _APPLE_FUNCTIONAL),
    _rule(r"^shield-magma-ifs-device[\w.-]*apple", _APPLE_FUNCTIONAL),
    _rule(r"^device-config\.(?:pcms\.apple\.com|v\.aaplimg\.com)$", _APPLE_FUNCTIONAL),
    _rule(r"^serverstatus\.apple\.com", _APPLE_FUNCTIONAL),
    _rule(r"^captive\.apple\.com$", _APPLE_FUNCTIONAL),
    _rule(r"(?:^|\.)apple\.map\.fastly\.net$", _APPLE_FUNCTIONAL),
    _rule(r"^h\d\.apis\.apple\.map\.fastly\.net$", _APPLE_FUNCTIONAL),
    # --- Google operational infrastructure ---
    _rule(r"^clients\d*\.(?:google\.com|l\.google\.com)$", _GOOGLE_FUNCTIONAL),
    _rule(r"^clients\.l\.google\.com$", _GOOGLE_FUNCTIONAL),
    _rule(r"^android\.clients\.google\.com$", _GOOGLE_FUNCTIONAL),
    _rule(r"^(?:mtalk|alt\d*-mtalk)\.google\.com$", _GOOGLE_FUNCTIONAL),
    _rule(r"^connectivitycheck\.(?:gstatic\.com|android\.com)$", _GOOGLE_FUNCTIONAL),
    # --- Notifications from other providers ---
    _rule(r"(?:^|[.-])spocpush[.-]", _verdict(
        "green", "push", "notification channel",
        "Channel for delivering real-time notifications to the app.",
        "Notifications are a function disclosed to the user and do not transfer a behavioral profile.",
    )),
    _rule(r"^(?:push|mtpush|pushstream|apns)\.", _verdict(
        "green", "push", "notification channel",
        "Channel for delivering real-time notifications to the app.",
        "Notifications are a function disclosed to the user and do not transfer a behavioral profile.",
    )),
    # --- Content delivery networks ---
    _rule(r"(?:^|\.)sc-cdn\.net$", _CDN_FUNCTIONAL),
    _rule(r"(?:^|\.)sc-static\.net$", _CDN_FUNCTIONAL),
    _rule(r"(?:^|\.)fbcdn\.net$", _CDN_FUNCTIONAL),
    _rule(r"(?:^|\.)mzstatic\.com", _CDN_FUNCTIONAL),
    _rule(r"^fonts\.(?:gstatic|googleapis)\.com$", _CDN_FUNCTIONAL),
)


# ---------------------------------------------------------------------------
# Red — explicit privacy violation
# ---------------------------------------------------------------------------

def _ad(name: str, source: str = "") -> dict[str, Any]:
    return _verdict(
        "red",
        "advertising",
        "advertising and tracking network",
        f"{name} advertising infrastructure: bidding, ad serving, and tracking of impressions and clicks linked to the device identifier.",
        f"The presence of {name} on the device is due to selling ad inventory and building a targeting profile, not to running the app.",
        source,
        device_data=True,
    )


def _attribution(name: str, source: str = "") -> dict[str, Any]:
    return _verdict(
        "red",
        "attribution",
        "install attribution and conversion tracking",
        f"{name} interface for linking app installs and subsequent events to an ad campaign and a device identifier.",
        f"{name} is an ad attribution platform that transmits device identifiers and events to a third party.",
        source,
        device_data=True,
    )
def _analytics(name: str, source: str = "") -> dict[str, Any]:
    return _verdict(
        "red",
        "behavior_analytics",
        "User behavior analytics",
        f"{name} endpoint aggregates usage events, screens, and sessions with a user or device ID.",
        f"{name} is a third party that builds a behavioral profile of the user across apps.",
        source,
        device_data=True,
    )


RED_RULES: tuple[tuple[re.Pattern[str], dict[str, Any]], ...] = (
    # --- Mobile ad intermediaries and platforms ---
    _rule(r"(?:^|\.)applovin\.com$", _ad("AppLovin", "https://www.applovin.com/privacy/")),
    _rule(r"(?:^|\.)(?:unityads|iads|mediation)\.unity3d\.com$", _ad("Unity Ads", "https://unity.com/legal/game-player-and-app-user-privacy-policy")),
    _rule(r"(?:^|\.)mz\.internal\.unity3d\.com$", _ad("Unity Ads")),
    _rule(r"(?:^|\.)supersonicads\.com$", _ad("ironSource / Supersonic")),
    _rule(r"(?:^|\.)(?:ironsrc|ironsource)\.\w+$", _ad("ironSource")),
    _rule(r"(?:^|\.)vungle\.com$", _ad("Vungle / Liftoff", "https://vungle.com/privacy/")),
    _rule(r"(?:^|\.)chartboost\.com$", _ad("Chartboost", "https://answers.chartboost.com/en-us/articles/200780269")),
    _rule(r"(?:^|\.)(?:moloco\.com|adsmoloco\.com)$", _ad("Moloco")),
    _rule(r"(?:^|\.)(?:liftoff\.io|liftoff-creatives\.io)$", _ad("Liftoff")),
    _rule(r"(?:^|\.)bidease\.com$", _ad("Bidease")),
    _rule(r"^bidease\.b-cdn\.net$", _ad("Bidease")),
    _rule(r"(?:^|\.)smadex\.com$", _ad("Smadex")),
    _rule(r"(?:^|\.)bidswitch\.net$", _ad("BidSwitch")),
    _rule(r"(?:^|\.)bidmachine\.io$", _ad("BidMachine")),
    _rule(r"(?:^|\.)(?:inmobi\.com|inmobicdn\.net)$", _ad("InMobi", "https://www.inmobi.com/privacy-policy")),
    _rule(r"(?:^|\.)(?:fyber\.com|inner-active\.mobi)$", _ad("Fyber / Inneractive")),
    _rule(r"(?:^|\.)(?:mtgglobals\.com|mobvista\.com|mintegral\.com)$", _ad("Mintegral / Mobvista")),
    _rule(r"(?:^|[.-])(?:pangle\.io|pglstatp\.com|byteoversea\.com)$", _ad("Pangle (ByteDance)")),
    _rule(r"pglstatp[\w.-]*\.akadns\.net$", _ad("Pangle (ByteDance)")),
    _rule(r"(?:^|[.-])pglstatp\.com[\w.-]*$", _ad("Pangle (ByteDance)")),
    _rule(r"pangle\.io[\w.-]*\.akadns\.net$", _ad("Pangle (ByteDance)")),
    _rule(r"(?:^|\.)vervegroupinc\.net$", _ad("Verve Group")),
    _rule(r"(?:^|\.)kayzen\.io$", _ad("Kayzen")),
    _rule(r"(?:^|\.)(?:appier\.net|adsappier\.com|appiersig\.com)$", _ad("Appier")),
    _rule(r"appier[\w.-]*\.akadns\.net$", _ad("Appier")),
    _rule(r"(?:^|\.)id5-sync\.com$", _ad("ID5 (Advertising Identity Sync)")),
    _rule(r"(?:^|\.)openx\.net$", _ad("OpenX")),
    _rule(r"(?:^|\.)teads\.tv$", _ad("Teads")),
    _rule(r"(?:^|\.)scorecardresearch\.com$", _analytics("comScore / ScorecardResearch")),
    _rule(r"(?:^|\.)bidr\.io$", _ad("Beeswax / Comcast")),
    _rule(r"(?:^|\.)(?:optimusbid\.com|silvermob\.com|adserv-us\.com|rtb-smartbidding\.com)$", _ad("Ad bidding network")),
    _rule(r"(?:^|\.)(?:digitaleast\.mobi|rapidbidding\.com|asight-stats\.com)$", _ad("Ad bidding network")),
    _rule(r"(?:^|\.)(?:adserverevent\.com|thezenads\.com|lacunads\.com|beecomarts\.com)$", _ad("Ad network")),
    _rule(r"(?:^|\.)(?:vrtcal\.com|siportb\.com|aarki\.net|adcolony\.com|tapjoy\.com)$", _ad("Ad network")),
    _rule(r"(?:^|\.)(?:smaato\.net|pubmatic\.com|rubiconproject\.(?:com|net)|adform\.net|mathtag\.com)$", _ad("Ad exchange platform")),
    _rule(r"rubiconproject[\w.-]*\.akadns\.net$", _ad("Magnite / Rubicon")),
    _rule(r"(?:^|\.)criteo\.(?:com|net)$", _ad("Criteo", "https://www.criteo.com/privacy/")),
    _rule(r"(?:^|\.)(?:reims-serving\.com|platformance\.io|dh-adtech\.net)$", _ad("Ad network")),
    _rule(r"(?:^|\.)amazon-adsystem\.com$", _ad("Amazon Advertising")),
    _rule(r"^mads\.amazon\.com$", _ad("Amazon Advertising")),
    _rule(r"advertising\.amazon\.dev$", _ad("Amazon Advertising")),
    _rule(r"advertising\.a2z\.com$", _ad("Amazon Advertising")),
    _rule(r"(?:^|\.)ad-host-backup[\w-]*\.oss-[\w-]+\.aliyuncs\.com$", _ad("Ad asset hosting")),
    _rule(r"(?:^|\.)envoy-track[\w.-]*$", _ad("Envoy Track")),
    _rule(r"(?:^|\.)ov1o\.com$", _ad("Envoy Track")),
    # --- Google Ads ---
    _rule(r"(?:^|\.)doubleclick\.net$", _ad("Google DoubleClick", "https://policies.google.com/technologies/ads")),
    _rule(r"(?:^|\.)googlesyndication\.com$", _ad("Google AdSense", "https://policies.google.com/technologies/ads")),
    _rule(r"(?:^|\.)googleadservices\.com$", _ad("Google Ads", "https://policies.google.com/technologies/ads")),
    _rule(r"(?:^|\.)googletagservices\.com$", _ad("Google Ad Manager")),
    _rule(r"^adservice\.google\.\w+$", _ad("Google Ads")),
    _rule(r"(?:^|\.)adtrafficquality\.google$", _ad("Google Ads")),
    _rule(r"^imasdk\.googleapis\.com$", _ad("Google IMA (Video Ads)")),
    _rule(r"(?:^|\.)googletagmanager\.com$", _verdict(
        "red", "tracking_loader", "Tracking tag loader",
        "Google Tag Manager: Loads analytics and ad tags on the page.",
        "Its function is to inject tracking tools themselves, so its privacy impact depends on what it loads.",
        "https://support.google.com/tagmanager/answer/6102821",
        device_data=True,
    )),
    _rule(r"(?:^|\.)google-analytics\.com$", _analytics("Google Analytics", "https://support.google.com/analytics/answer/11593727")),
    _rule(r"^analytics(?:-alv)?\.google\.com$", _analytics("Google Analytics")),
    _rule(r"^app-measurement\.com$", _analytics("Google Analytics for Firebase", "https://firebase.google.com/docs/analytics")),
    _rule(r"^firebaselogging(?:-pa)?\.googleapis\.com$", _analytics("Firebase Analytics", "https://firebase.google.com/docs/analytics")),
    _rule(r"(?:^|\.)app-analytics-services\.com$", _analytics("Google App Analytics")),
    _rule(r"(?:^|\.)app-ads-services\.com$", _ad("Google App Ads")),
    # --- Attribution and install tracking ---
    _rule(r"(?:^|\.)appsflyer(?:sdk)?\.com$", _attribution("AppsFlyer", "https://www.appsflyer.com/legal/services-privacy-policy/")),
    _rule(r"(?:^|\.)adjust\.(?:com|io|net\.in|world|cn)$", _attribution("Adjust", "https://www.adjust.com/terms/privacy-policy/")),
    _rule(r"(?:^|\.)singular\.net$", _attribution("Singular")),
    _rule(r"(?:^|\.)branch\.io$", _attribution("Branch", "https://help.branch.io/developer-hub/docs/track-branch-events")),
    _rule(r"(?:^|\.)kochava\.com$", _attribution("Kochava")),
    _rule(r"(?:^|\.)tenjin\.io$", _attribution("Tenjin")),
    # --- Behavioral analytics and marketing platforms ---
    _rule(r"(?:^|\.)amplitude\.com$", _analytics("Amplitude", "https://amplitude.com/docs/apis/analytics/http-v2")),
    _rule(r"(?:^|\.)(?:mixpanel\.com|mxpnl\.com)$", _analytics("Mixpanel")),
    _rule(r"(?:^|\.)segment\.(?:io|com)$", _analytics("Segment")),
    _rule(r"(?:^|\.)moengage\.com$", _analytics("MoEngage")),
    _rule(r"(?:^|\.)clevertap[\w-]*\.com$", _analytics("CleverTap")),
    _rule(r"(?:^|\.)braze\.com$", _analytics("Braze")),
    _rule(r"(?:^|\.)pushwoosh\.com$", _analytics("Pushwoosh")),
    _rule(r"(?:^|\.)dataroid\.com$", _analytics("Dataroid")),
    _rule(r"(?:^|\.)rudderstack\.com$", _analytics("RudderStack")),
    _rule(r"(?:^|\.)clarity\.ms$", _verdict(
        "red", "session_analytics", "User session recording",
        "Microsoft Clarity: Records mouse movements, clicks, and scrolling, and replays the session.",
        "Session replay captures detailed user interaction within the page.",
        "https://learn.microsoft.com/en-us/clarity/",
        device_data=True,
    )),
    _rule(r"(?:^|\.)(?:hotjar\.com|fullstory\.com|smartlook\.com|mouseflow\.com)$", _verdict(
        "red", "session_analytics", "User session recording",
        "A session replay tool that captures user interaction within the page.",
        "Session capture includes clicks, scrolling, and sometimes field content.",
        device_data=True,
    )),
    _rule(r"(?:^|\.)demdex\.net$", _verdict(
        "red", "audience_tracking", "build advertising audience",
        "Adobe Audience Manager: Synchronize identifiers and build audience segments across sites.",
        "A data management platform designed to link user behavior across multiple sites.",
        "https://experienceleague.adobe.com/docs/audience-manager.html",
        device_data=True,
    )),
    _rule(r"(?:^|\.)(?:adobedtm\.com|omtrdc\.net)$", _verdict(
        "red", "tracking_loader", "Adobe Tag Loader",
        "Adobe Experience Platform Tags: Loads analytics and targeting tags.",
        "Its function is to inject measurement and targeting tools into the app or site.",
        device_data=True,
    )),
    _rule(r"(?:^|\.)tapad\.com$", _verdict(
        "red", "audience_tracking", "cross-device identity linking",
        "Tapad: Maps and links a user's various devices to a single identity.",
        "Cross-device linking is the core of the service, constituting explicit tracking.",
        device_data=True,
    )),
    # --- Social Platform Analytics ---
    _rule(r"^analytics[\w-]*\.(?:tiktok\.com|tiktokw\.us|tiktokv\.com)$", _analytics("TikTok Analytics")),
    _rule(r"^(?:rt)?log\d*-normal[\w-]*\.tiktokv\.com$", _analytics("TikTok Logging")),
    _rule(r"^app-analytics[\w-]*\.snapchat\.com$", _analytics("Snap Analytics")),
    _rule(r"^analytics\.twitter\.com$", _analytics("X / Twitter Analytics")),
    _rule(r"^ads-api\.(?:twitter\.com|x\.com)$", _ad("X / Twitter Ads")),
    _rule(r"(?:^|\.)ads-twitter\.com$", _ad("X / Twitter Ads")),
    _rule(r"^(?:snap|px)\.(?:licdn\.com|ads\.linkedin\.com)$", _ad("LinkedIn Ads")),
    _rule(r"^px\.ads\.linkedin\.com$", _ad("LinkedIn Ads")),
    _rule(r"^snap\.licdn\.com$", _ad("LinkedIn Insight")),
    # --- Tracking within specific apps ---
    _rule(r"(?:^|\.)honey\.io$", _analytics("Honey (PayPal) — shopping tracking")),
    _rule(r"(?:^|\.)tk0x1\.com$", _analytics("Third-party Telemetry SDK")),
    _rule(r"^(?:analytics|ipm-static)[\w.-]*\.(?:avcdn\.net|avast\.com)$", _analytics("Avast Analytics")),
    _rule(r"(?:^|\.)productanalytics\.deliveryhero\.net$", _analytics("Delivery Hero Product Analytics")),
    _rule(r"^data-sdk-uuid-log[\w.-]*\.", _verdict(
        "red", "device_telemetry", "device ID logging",
        "A logging endpoint that sends a unique device ID with every event.",
        "Sending the device UUID to a logging server enables cross-session user tracking.",
        device_data=True,
    )),
    _rule(r"^maplocatesdksnapshot[\w.-]*\.", _verdict(
        "red", "location", "periodic location snapshot",
        "An endpoint that uploads location snapshots from the maps SDK.",
        "Periodically uploading location to a third party constitutes explicit tracking.",
        device_data=True,
    )),
    _rule(r"^route-stats[\w.-]*\.", _verdict(
        "red", "location", "route and location statistics",
        "A statistics endpoint for routes linked to user movement.",
        "Route data reveals the user's mobility patterns.",
        device_data=True,
    )),
    # --- Tracking within banking and government apps: transmission continues even if the feature is disabled ---
    _rule(r"^sensors?[\w-]*-?api\.", _verdict(
        "red", "behavior_analytics", "User behavior analytics",
        "SensorsData endpoint for capturing screens, clicks, and user paths within the app.",
        "A complete behavior analysis platform inside a financial app, continuing to send data even after tracking is disabled.",
        device_data=True,
    )),
    _rule(r"^ep\d+\.facebook\.com$", _verdict(
        "red", "attribution", "Meta App Events",
        "Facebook SDK event endpoint: app opens, purchases, and custom events with device ID.",
        "Meta uses these events for targeting and campaign measurement, even within apps unrelated to Facebook.",
        "https://developers.facebook.com/docs/app-events/",
        device_data=True,
    )),
    _rule(r"(?:^|\.)browser-intake-datadoghq\.(?:com|eu)$", _verdict(
        "red", "session_analytics", "User Session Aggregation",
        "Datadog RUM: uploads user interactions, errors, and screen paths with a persistent session ID.",
        "Detailed session aggregation in a financial app, continuing even after tracking is disabled.",
        "https://docs.datadoghq.com/real_user_monitoring/",
        device_data=True,
    )),
    # User event aggregation points: upload 'what you did inside the app', not operational health.
    # Separate from the service domain; blocking them does not disrupt the app.
    _rule(r"^(?:dp-)?event-collector\.|^log-report\.", _verdict(
        "red", "behavior_analytics", "User Event Aggregation",
        "In-app usage and screen event aggregation point.",
        "Detailed behavioral events sent from a financial app despite tracking being disabled, "
        "and separate from the service domain, so the app does not stop if blocked.",
        device_data=True,
    )),
    _rule(r"(?:^|\.)infobip\.com$", _verdict(
        "red", "marketing_automation", "Communication and Marketing Platform",
        "Infobip: sending campaigns and messages with delivery, open, and interaction tracking.",
        "Marketing engagement platform that transfers user ID and behavior to a third party.",
        device_data=True,
    )),
    _rule(r"(?:^|\.)iadsdk\.apple\.com[\w.-]*$", _ad("Apple Search Ads SDK", "https://searchads.apple.com/privacy")),
    _rule(r"inmobi[\w-]*\.trafficmanager\.net$", _ad("InMobi")),
    _rule(r"(?:^|\.)moloco[\w.-]*\.fastly\.net$", _ad("Moloco")),
    _rule(r"^ssp-prod-traffic-mgr[\w-]*\.trafficmanager\.net$", _ad("Ad Display Platform")),
    _rule(r"^dsp-ad-cache[\w-]*\.trafficmanager\.net$", _ad("Ad Request Platform")),
)


# ---------------------------------------------------------------------------
# Orange — worth monitoring without certain confirmation of violation
# ---------------------------------------------------------------------------

_CRASH = _verdict(
    "orange",
    "crash_diagnostics",
    "Crash Diagnostics",
    "Endpoint for receiving crash reports and error traces from the app.",
    "The stated purpose is fixing crashes, but the report may contain device ID and usage context; monitored but not blocked.",
    device_data=True,
)

_RUM = _verdict(
    "orange",
    "real_user_monitoring",
    "First-party Performance Measurement",
    "Measuring response time and interface errors within the same entity's app.",
    "Non-advertising performance measurement, but it links events to the user session; worth monitoring.",
    device_data=True,
)

_DEVICE_ID = _verdict(
    "orange",
    "device_operational",
    "Device identifier and operational settings",
    "Register the app instance on the device and retrieve its settings and notification keys.",
    "Uses a fixed device identifier, which is necessary for operation but allows linking; monitored.",
    device_data=True,
)

_LOCATION_OP = _verdict(
    "orange",
    "location",
    "Operational location services",
    "The location infrastructure relied upon by maps and system 'Location'.",
    "Location is sensitive data, but its use here is a user-requested function; monitored, not blocked.",
    device_data=True,
)

_PERSONAL_DATA = _verdict(
    "orange",
    "privacy_data",
    "Access to personal data",
    "An interface that reads contacts, profile, or place history for the user account.",
    "Genuine personal data, but within the user's own account and service; monitored.",
    device_data=True,
)

ORANGE_RULES: tuple[tuple[re.Pattern[str], dict[str, Any]], ...] = (
    # --- Fault diagnosis ---
    _rule(r"(?:^|\.)sentry\.io$", _CRASH),
    _rule(r"(?:^|\.)ingest\.(?:us\.|de\.)?sentry\.io$", _CRASH),
    _rule(r"^sentry[\w.-]*\.", _CRASH),
    _rule(r"(?:^|\.)bugsnag\.com$", _CRASH),
    _rule(r"(?:^|\.)appcenter\.ms$", _CRASH),
    _rule(r"(?:^|\.)crashlytics\.com$", _CRASH),
    _rule(r"^crashlyticsreports-pa\.googleapis\.com$", _CRASH),
    # --- Performance measurement and monitoring ---
    _rule(r"(?:^|\.)nr-data\.net", _RUM),
    _rule(r"(?:^|\.)cloudflareinsights\.com$", _RUM),
    _rule(r"(?:^|\.)pingdom\.net$", _RUM),
    _rule(r"(?:^|\.)(?:launchdarkly\.com|oaistatsig\.com|statsig\.com)$", _RUM),
    _rule(r"^collector\.(?:github\.com|githubapp\.com)$", _RUM),
    # Measure interface performance within the same entity: measures response time and errors, not
    # user action content, so it remains orange even with banking or government apps.
    _rule(r"^(?:eum|rum|apm)\.", _RUM),
    _rule(r"^(?:mobile-)?telemetry[\w.-]*\.(?:tradingview\.com|forzafootball\.net|elb\.amazonaws\.com)$", _RUM),
    _rule(r"(?:^|\.)events\.data\.microsoft\.com$", _verdict(
        "orange", "device_telemetry", "Microsoft usage measurement",
        "Channel for measuring usage and faults in Microsoft applications.",
        "Operational and product data from the provider itself; can be reduced via privacy settings.",
        "https://learn.microsoft.com/en-us/windows/privacy/",
        device_data=True,
    )),
    _rule(r"^mrodevicemgr\.officeapps\.live\.com$", _DEVICE_ID),
    _rule(r"(?:^|\.)stats[\w.-]*\.(?:paypal|norton)\.com$", _RUM),
    _rule(r"stats\.norton\.com[\w.-]*trafficmanager\.net$", _RUM),
    _rule(r"(?:^|\.)aptabase[\w.-]*", _RUM),
    _rule(r"(?:^|\.)helpscout\.net$", _verdict(
        "orange", "engagement_tracking", "Support and chat tool",
        "In-app support tool that logs conversation initiation and user context.",
        "The stated purpose is technical support, but it carries a session ID; monitored.",
        device_data=True,
    )),
    # --- Device identifiers and remote settings ---
    _rule(r"^firebase(?:installations|remoteconfig|inappmessaging)\.googleapis\.com$", _DEVICE_ID),
    _rule(r"^(?:iid|device-provisioning)\.googleapis\.com$", _DEVICE_ID),
    _rule(r"(?:^|\.)revenuecat\.com$", _DEVICE_ID),
    _rule(r"^notifications-pa\.googleapis\.com$", _DEVICE_ID),
    _rule(r"^smart\.\w+\.com$", _verdict(
        "orange", "device_integrity", "Device integrity check",
        "Check for jailbreaking and developer mode before allowing sensitive operations.",
        "Legitimate defense against fraud in banking apps, but it reads device state; monitored.",
        developer_check=True,
        device_data=True,
    )),
    # --- Location ---
    _rule(r"(?:^|\.)ls\.apple\.com$", _LOCATION_OP),
    _rule(r"^gsp[\w-]*-ssl\.ls\.apple\.com$", _LOCATION_OP),
    _rule(r"^iphone-ld\.(?:apple\.com|g\.aaplimg\.com)$", _LOCATION_OP),
    _rule(r"^wps[\w.-]*\.(?:apple\.com|v\.aaplimg\.com)$", _LOCATION_OP),
    _rule(r"[\w-]*wps-prod\.apple\.com$", _LOCATION_OP),
    _rule(r"^locationhistory[\w-]*-pa\.googleapis\.com$", _LOCATION_OP),
    _rule(r"^location\.se-platform\.com$", _LOCATION_OP),
    _rule(r"^geolocation\.onetrust\.com$", _LOCATION_OP),
    # --- Personal data within the user's account ---
    _rule(r"^(?:people|peoplestack)-pa\.googleapis\.com$", _PERSONAL_DATA),
    _rule(r"^p\d+-fmf\.icloud\.com$", _verdict(
        "orange", "location", "Share location with friends",
        "The 'Find My Friends' service for location sharing, enabled by the user.",
        "Location sharing with explicit user consent; monitored to ensure it remains intentional.",
        device_data=True,
    )),
    _rule(r"^fmf\.[\w.-]*apple-dns\.net$", _verdict(
        "orange", "location", "Share location with friends",
        "The 'Find My Friends' service for location sharing, enabled by the user.",
        "Location sharing with explicit user consent; monitored to ensure it remains intentional.",
        device_data=True,
    )),
    _rule(r"^content-autofill\.googleapis\.com$", _PERSONAL_DATA),
    # --- Customization and Recommendations ---
    _rule(r"^(?:discover|growth|optimizationguide)-pa\.googleapis\.com$", _verdict(
        "orange", "personalization", "Content customization and recommendations",
        "Interface that fetches personalized recommendations and content based on user account activity.",
        "Personalization relies on activity history but occurs within a user-used service; monitored.",
        device_data=True,
    )),
    _rule(r"^ogads-pa\.(?:googleapis\.com|clients6\.google\.com)$", _verdict(
        "orange", "personalization", "Promotions within Google services",
        "Interface displaying Google service promotions within the app.",
        "Promotion of the provider's own services, not external ad networks; monitored.",
        device_data=True,
    )),
    # --- Privacy-preserving Ad Attribution ---
    _rule(r"^api-adservices\.apple\.com$", _verdict(
        "orange", "attribution", "Apple-style Ad Attribution",
        "AdServices interface for aggregated installation attribution that does not reveal device identity.",
        "Ad attribution designed by Apple to be aggregated and without individual identifiers; monitored.",
        "https://developer.apple.com/documentation/adservices",
        device_data=True,
    )),
    _rule(r"requestattribution[\w.-]*\.apple\.com$", _verdict(
        "orange", "attribution", "Apple-style Ad Attribution",
        "SKAdNetwork endpoint for sending aggregated conversion signals.",
        "Aggregated attribution signal without user identifier; monitored.",
        device_data=True,
    )),
    # --- Voice Assistants ---
    _rule(r"^guzzoni\.apple\.com$", _verdict(
        "orange", "assistant", "Voice Assistant",
        "Server processing Siri requests.",
        "Sends request text or audio for processing; required functionality but sensitive, so monitored.",
        device_data=True,
    )),
    _rule(r"digitalassistant\.oci\.oraclecloud\.com$", _verdict(
        "orange", "assistant", "Chat Assistant",
        "An in-app cloud-based chat assistant service.",
        "Sends chat text to the cloud; monitored.",
        device_data=True,
    )),
    # --- Consent and Privacy Platforms ---
    _rule(r"(?:^|\.)(?:onetrust\.com|cookielaw\.org|privacy-center\.org|usercentrics\.eu)$", _verdict(
        "orange", "consent_management", "Consent Management",
        "Platform for displaying the consent window and storing the user's choice.",
        "Its stated purpose is privacy compliance, but it determines location and stores a consent ID; monitored.",
        device_data=True,
    )),
    # --- General Cloud Storage Hosting Mixed Content ---
    _rule(r"^storage\.googleapis\.com$", _verdict(
        "orange", "general_network", "General Cloud Storage",
        "General storage used by many applications for their files, and sometimes for advertising materials.",
        "The destination itself is neutral; content cannot be determined from the domain name alone.",
    )),
    _rule(r"content-storage-download\.googleapis\.com$", _verdict(
        "orange", "general_network", "General Cloud Storage",
        "Downloading files from public Google storage.",
        "The destination itself is neutral; content cannot be determined from the domain name alone.",
    )),
    # --- System Metrics ---
    _rule(r"^metrics\.icloud\.com$", _verdict(
        "orange", "system_metrics", "Apple System Metrics",
        "Operational metrics endpoint for Apple services and iCloud.",
        "System metrics from the device provider itself; monitored but not blocked.",
        "https://www.apple.com/privacy/",
        device_data=True,
    )),
    _rule(r"^shepherd\.avcdn\.net$", _verdict(
        "orange", "remote_config", "Remote Settings for Security Product",
        "Fetching protection product settings and features remotely.",
        "Operational setting, but the provider has a history of sharing browsing data; closely monitored.",
        device_data=True,
    )),
    # --- Social Platforms via Browser ---
    _rule(r"^(?:www\.)?(?:facebook\.com|twitter\.com|x\.com|linkedin\.com|snapchat\.com|t\.co)$", _verdict(
        "orange", "social_service", "Social Platform",
        "Social platform domain that may come from a direct visit or from an embedded button/pixel on another site.",
        "DNS alone cannot distinguish between an intentional visit and embedded tracking; monitored.",
        device_data=True,
    )),
    # --- Undecided ---
    _rule(r"^solstice\.panthertechnology\.com$", _verdict(
        "orange", "general_network", "Undetermined destination",
        "Third-party destination whose function is unclear from public sources.",
        "Insufficient evidence of tracking or operational function; remains under observation.",
    )),
)


_ALL_RULES: tuple[tuple[re.Pattern[str], dict[str, Any]], ...] = (
    GREEN_OVERRIDES + RED_RULES + ORANGE_RULES
)


LOCAL_AGREEMENT = "Built-in catalog"


def catalog_verdict(domain: str) -> dict[str, Any] | None:
    """The built-in catalog's verdict in review form, used when AI review is off. Red from the catalog is
    reviewed knowledge (a documented tracker or ad network), so it may be blocked; every safety gate still applies."""
    entry = verdict_for(domain)
    color = str((entry or {}).get("risk") or "")
    if color not in ("green", "orange", "red"):
        return None
    return {
        "color": color, "confidence": 95, "category": str(entry.get("category") or ""),
        "purpose": str(entry.get("summary") or ""), "reason": str(entry.get("reason") or entry.get("summary") or ""),
        "blockSafe": color == "red", "agreement": LOCAL_AGREEMENT, "provider": "built-in catalog", "model": "",
    }


def verdict_for(domain: str) -> dict[str, Any] | None:
    """Return the reviewed verdict for the domain, or ``None`` if no rule matches."""
    name = (domain or "").strip().strip(".").lower()
    if not name:
        return None
    for pattern, verdict in _ALL_RULES:
        if pattern.search(name):
            return verdict
    return None


# ---------------------------------------------------------------------------
# Escalation based on application context
# ---------------------------------------------------------------------------
# Banking, government, and telecom applications handle user identity and funds,
# and the user has disabled tracking on the device (``defaults.tracking = deny``). Any
# behavioral collection point continuing to operate from these apps is treated as an explicit violation, not just suspicion.

SENSITIVE_APP_PATTERN = re.compile(
    r"alinma|sabb|\bsab\b|derayah|sahm|vcfc|d360|barraq|tabby|riyad|rajhi"
    r"|\bsnb\b|\banb\b|\bbsf\b|\bgib\b|meem|paypal|mada|stcpay|urpay"
    r"|absher|tawakkalna|nafath|myid|moi\.|gov\.sa|gov\.nic|madrasati|t4edu"
    r"|moe\.gov|sdaia|huduri|availo|mobily|\bstc\b|zain",
    re.I,
)

# Categories representing behavioral collection with no operational necessity: they monitor "what the user did".
# Fault diagnosis, performance measurement (real_user_monitoring), and operation IDs remain
# orange even within a banking app, because they measure app health, not user behavior—
# and detecting a violation in one app does not make all its domains violations.
TRACKING_CATEGORIES = frozenset(
    {
        "advertising",
        "advertising_tracking",
        "attribution",
        "audience_tracking",
        "behavior_analytics",
        "engagement_tracking",
        "marketing_automation",
        "session_analytics",
        "tracking_loader",
    }
)

_SENSITIVE_ESCALATION = _verdict(
    "red",
    "behavior_analytics",
    "Tracking within a sensitive app despite the feature being disabled",
    "A behavioral collection point operating within a banking or government app that handles user identity and funds.",
    "The tracking feature is disabled in the device policy, yet transmission continues; collection without consent is an explicit violation.",
    device_data=True,
)


def escalate_for_context(
    domain: str,
    risk: str,
    category: str,
    contexts: list[str] | tuple[str, ...] | None,
) -> dict[str, Any] | None:
    """Escalate the verdict to red if it is behavioral collection within a sensitive app.

    Escalation does not apply to operational domains. Detecting a violation in one app does not make all its domains
    violations; the violating domain is always separate from the app's operational path, and blocking
    an operational domain disrupts the app for the user without benefit.
    """
    if risk == "red":
        return None
    if category not in TRACKING_CATEGORIES:
        return None
    if not is_block_safe(domain, category):
        return None
    haystack = " ".join(str(item) for item in (contexts or []))
    if not haystack or not SENSITIVE_APP_PATTERN.search(haystack):
        return None
    return _SENSITIVE_ESCALATION


# ---------------------------------------------------------------------------
# Is blocking the domain safe for the app's functionality?
# ---------------------------------------------------------------------------
# The color describes privacy, while this field describes operational impact. No domain
# should be suggested for blocking unless `blockSafe` is true, regardless of it being red.

# Operational paths: authentication, service interfaces, certificates, notifications, updates, and safety gateways.
# Blocking them prevents access or disables the app.
OPERATIONAL_PATTERN = re.compile(
    r"^(?:api|api\d+|gw-api|gateway|auth|login|oauth|sso|idp|account|accounts|id|"
    r"identity|token|session|cdn|scdn|mcdn|rcdn|static|assets|img|images|media|"
    r"content|config|configuration|configserver|settings|update|updates|ota|"
    r"push|apns|fcm|mqtt|ws|socket|stream|chat|support|pay|payment|checkout|"
    r"secure|verify|attest|ocsp|crl|smart|shield|guard|risk|kyc|nafath|status|"
    r"health|www|m|mobile|app|web)\b",
    re.I,
)

# Names that indicate the domain is a collection endpoint, not a runtime path.
COLLECTOR_PATTERN = re.compile(
    r"(?:^|[.-])(?:analytics?|analytic|telemetry|metrics?|beacon|beacons|pixel|"
    r"track|tracking|tracker|events?|event-collector|collector|logging|logs?|"
    r"log-report|sensors?-api|insight|insights|measure|measurement|attribution|"
    r"adservice|ads?|adserver|adsdk|rtb|bid|bidder|dsp|ssp|impression|click|"
    r"conversion|dataroid|appsflyer|adjust|amplitude|mixpanel|segment|braze|"
    r"clarity|demdex|doubleclick|criteo|inmobi|applovin|moloco|liftoff|"
    # Pure collection companies: every host of theirs runs a collection endpoint even if it
    # starts with static, cdn, api or www.
    r"hotjar|heapanalytics|adsafeprotected|4dsply|antibanads|appdynamics|cloudflareinsights|"
    r"company-target|dropboxexperiment|googletagmanager|googleadservices|ebayadservices|"
    r"instabug|klaviyo|pocustrack|rubiconproject|adnxs|sprig|taboola|zoominfo|userpilot|ojrq|"
    r"bugsnag|mshopbugsnag|bdtelemetry|advertising|"
    # Review 2026-10-29: Common Room, FullContact, LiveRamp, Zeta, Oracle Responsys and ByteDance measurement.
    r"cr-relay|fullcontact|rlcdn|boomtrain|pushio|gtm\.byteoversea|"
    # Mobile review: anonymous trackers whose caller does not declare collection by name.
    r"stbid|uxcam|akstat|applvn|lenzmx|lenkmio|ahdmw|cadmus2?\.script|sonar-xp\.script|rayjump|relevant-digital|flurry|"
    r"digitaltarget|digitalturbine|hybrid\.ai|axon\.ai|forester|fls-na|fls-eu|unagi(?:-na|-eu)?|evt\.ilovepdf|lijit|lporirxe|"
    r"gator\.volces|apmplus\.volces|tab\.volces|catfront|catdot|cat\.sh\.vip|catx-v6|outspot-[a-z]+-vip\d|t-odx|ipds\.opr|newrelic|"
    r"id5-sync|mc\.yandex|mtrtb|meetscale|adrta|g2afse|trckswrm|iponweb|prism-report-knb|lx\.meituan|telecid|browser-intake-us5-datadoghq|"
    r"intentiq|admthop|iaudienc|kazfv|pxltgr|sparteo|tagsrvcs|adsmeasurement|awstrack|gpm\.byteoversea|isx\.unity3d|brsrvr|"
    r"bat-bing-com|c-bing-com|c\.bing|alb\.reddit|consumer\.intel|"
    # Review 2026-10-30: Tealium tags, game-ad assessment and Unity's data platform.
    r"tiqcdn|webcontentassessor|cdp\.internal\.unity3d|"
    # Pure collectors whose guessed category kept them open.
    r"admixer|rudderlabs|posthog|quantummetric|datadoghq|sharethrough|creativeadv|iapplogcdn|instabug|"
    r"crashlogs?|tr\.snapchat|aax)(?:[.-]|$)",
    re.I,
)

# Pure collection categories: whatever the host name, the app's operation does not depend on them.
_PURE_COLLECTION_CATEGORIES = frozenset(
    {
        "advertising",
        "crash_diagnostics",
        "advertising_tracking",
        "attribution",
        "audience_tracking",
        "behavior_analytics",
        "engagement_tracking",
        "marketing_automation",
        "session_analytics",
        "telemetry",
        "tracking_loader",
    }
)

# Categories that must never be suggested for blocking because they are a runtime path
# or shared system infrastructure. Categories the local classifier guesses from the name alone
# (domain_classifier: "operational service" and "general network service") are kept out of this
# list so they do not override the reviewed collector list.
_GUESSED_CATEGORIES = frozenset({"functional_service", "general_network"})

_NEVER_BLOCK_CATEGORIES = frozenset(
    {
        "authentication",
        "core_api",
        "device_integrity",
        "device_operational",
        "dns_service_discovery",
        "expected_health_data",
        "functional_service",
        "infrastructure",
        "location",
        "privacy_protection",
        "push",
        "remote_config",
        "service_identity",
    }
)


# ---------------------------------------------------------------------------
# Domain role: is it part of the app's function or an addition to it?
# ---------------------------------------------------------------------------
# A single app calls two kinds of domains, not one. An attendance app calls domains on which
# the daily check-in depends, whose blocking defeats the purpose it was installed for, and
# alongside them domains unrelated to check-in at all: third-party measurement, advertising
# and attribution, whose blocking is exactly what is wanted. So the question is not "who calls
# this domain" but "does it serve its caller's function or add to it".

# Apps whose declared purpose requires the network: attendance, location, health, fitness,
# maps and weather.
PURPOSE_APPS = re.compile(
    r"huduri|hudur|availo|hather|attendance|checkin|check-in|"
    r"health|sehha|sehhaty|seha|moh\.gov|fitness|workout|activity|"
    r"sport|steps?|heart|sleep|band|watch|wearable|zepp|mifit|amazfit|"
    r"garmin|fitbit|polar|suunto|withings|samsunghealth|shealth|"
    r"maps?\b|khareta|navigation|navi|weather|find(?:my)?|fmf",
    re.I,
)
# Describe the app's purpose by category. This description is sent to the model to judge the domain's relevance.
# By function, along with the app name since 2026-10-05 (no data privacy before models).
PURPOSE_CATEGORIES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"huduri|hudur|availo|hather|attendance|checkin|check-in", re.I),
        "Attendance and time tracking app: its function is to determine location at check-in and send the fingerprint",
    ),
    (
        re.compile(r"health|sehha|fitness|workout|sport|steps?|heart|sleep|band|"
                   r"watch|wearable|zepp|mifit|amazfit|garmin|fitbit|shealth", re.I),
        "Health and fitness app: its function is to monitor body data and upload it for display to the user",
    ),
    (re.compile(r"maps?\b|khareta|navigation|navi|find(?:my)?|fmf", re.I),
     "Maps and navigation app: its function is location and downloading maps"),
    (re.compile(r"weather", re.I), "Weather app: its function is location and weather data"),
    (re.compile(r"bank|alinma|sabb|rajhi|snb|anb|riyad|derayah|pay|tabby", re.I),
     "Financial app: its function is authentication and account operations"),
    (re.compile(r"absher|tawakkalna|nafath|myid|gov", re.I),
     "Government app: its function is identity and official services"),
    (re.compile(r"puzzle|game|woodenblock|mania", re.I),
     "Game: its function is local gameplay and does not require sending data to third parties"),
)


def caller_purpose(callers: tuple[str, ...] = ()) -> str:
    """Class object called by description rather than name, suitable for sending to an external provider."""
    joined = " ".join(str(item) for item in callers if item)
    if not joined.strip():
        return ""
    for pattern, label in PURPOSE_CATEGORIES:
        if pattern.search(joined):
            return label
    return ""


# Hostnames indicating downloadable content: maps, packages, resources, and settings.
# Blocking any of them breaks offline map downloads, which has actually occurred.
DOWNLOADABLE_CONTENT = re.compile(
    r"(?:^|[.-])(?:map|maps|tile|tiles|geo|region|regions|offline|"
    r"contentcenter|contentdownload|configdownload|download|downloads|"
    r"pkg|package|packages|res|resource|resources|firmware|ota)(?:[.-]|$)",
    re.I,
)

# Root domains whose function is delivering images and files displayed by the app.
CONTENT_DELIVERY_BASE = re.compile(
    r"imagedelivery|imgix|cloudinary|akamaized|fastly(?:cdn)?|jsdelivr|unpkg", re.I
)

# Third-party services required for app operation: device registration for notifications, fetching
# settings, authentication, and storage. Blocking them prevents the app from working, not just tracking.
THIRD_PARTY_FUNCTIONAL = re.compile(
    r"firebaseinstallations|firebaseremoteconfig|firebasestorage|firestore|"
    r"firebasedatabase|identitytoolkit|securetoken|fcmtoken|"
    r"iid\.googleapis|instanceid|device-provisioning|"
    r"(?:^|\.)fcm\.|android\.(?:clients\.)?google|safebrowsing|"
    r"(?:^|\.)sts\.|appattest|devicecheck",
    re.I,
)

# Third-party services unnecessary for core functionality regardless of the calling app: usage
# analytics, crash reports, in-app marketing messages, and performance monitoring.
THIRD_PARTY_EXTRA = re.compile(
    r"app-measurement|firebaselogging|firebaseinappmessaging|crashlytics|"
    r"app-analytics-services|growth-pa|google-analytics|googletagmanager|"
    r"doubleclick|adservice\.google|ads\.google|"
    r"(?:^|[.-])apm(?:[.-]|$)|(?:^|[.-])rum(?:[.-]|$)|quantummetric|"
    r"contentsquare|posthog|mixpanel|amplitude|heap|fullstory|hotjar|"
    r"appsflyer|adjust\.com|branch\.io|singular|kochava|tenjin",
    re.I,
)

# Manufacturer domain families: the app package does not textually resemble its domain, so linking is required.
VENDOR_DOMAIN_FAMILIES: tuple[tuple[re.Pattern[str], tuple[str, ...]], ...] = (
    (
        re.compile(r"huawei|hihonor|\bhonor\b", re.I),
        ("hicloud.com", "dbankcloud.com", "dbankcloud.cn", "dbankcloud.eu",
         "dbankcloud.asia", "dbankcdn.com", "dbankcdn.cn", "huawei.com", "vmall.com"),
    ),
    (re.compile(r"samsung", re.I),
     ("samsunghealth.com", "samsungcloud.com", "samsungqbe.com", "samsung.com")),
    (re.compile(r"garmin", re.I), ("garmin.com", "garmin.cn")),
    (re.compile(r"fitbit", re.I), ("fitbit.com",)),
    (re.compile(r"zepp|amazfit|mifit|xiaomi", re.I),
     ("zepp.com", "huami.com", "amazfit.com", "mi.com")),
    (re.compile(r"symantec|norton", re.I), ("norton.com", "symantec.com", "nortonlifelock.com")),
    (re.compile(r"whatsapp", re.I), ("whatsapp.net", "whatsapp.com")),
    (re.compile(r"zhiliaoapp|musically|tiktok|bytedance", re.I),
     ("tiktokv.com", "tiktokcdn.com", "byteoversea.com", "musical.ly")),
    (re.compile(r"facebook|instagram|meta", re.I),
     ("facebook.com", "fbcdn.net", "fbsbx.com", "instagram.com", "cdninstagram.com")),
    (re.compile(r"opera", re.I), ("opera.com", "operacdn.com")),
    (re.compile(r"keeta|meituan", re.I), ("mykeeta.com", "meituan.com")),
    (re.compile(r"google|chrome|youtube|gmail", re.I),
     ("googleapis.com", "google.com", "gstatic.com", "googleusercontent.com", "ggpht.com")),
    (re.compile(r"apple", re.I), ("apple.com", "icloud.com", "mzstatic.com")),
    (re.compile(r"microsoft|outlook|office", re.I),
     ("microsoft.com", "office.com", "live.com", "msn.com")),
)

# Paths that the user's login or notification delivery depends on: blocking them blocks the user, not the tracker.
FEDERATED_LOGIN_OR_DELIVERY = re.compile(
    r"(?:^|\.)accounts\.google\.com$|(?:^|\.)appleid\.apple\.com$|"
    r"(?:^|\.)(?:login|signin|auth|oauth|sso|account|accounts)\.|"
    r"(?:^|[.-])(?:pinpoint|push|apns|fcm)(?:[.-]|$)",
    re.I,
)

# Ad and bidding platforms are identified by their root domain, not their subdomain,
# because the subdomain is chosen by the platform itself: a bidding network that names
# its host `notify` does not become a notification gateway, so the protections that
# cover login and delivery paths do not apply to it.
AD_PLATFORM_BASE = re.compile(
    r"^(?:rtb|adx|dsp|ssp|adserver|adservice|adsystem|bidder|bidding)"
    r"|criteo|pubmatic|openx|smaato|inmobi|applovin|moloco|liftoff|vungle"
    r"|ironsource|chartboost|tapjoy|mintegral|pangle|loopme|taboola|outbrain"
    r"|teads|smartadserver|adcolony|fyber|rubicon|magnite|trafficguard"
    r"|doubleverify|adnxs|appnexus|admixer|adtech|adroll|zeotap|lotame|liveramp"
    # An ad network remains an ad network even if it belongs to the app's own owner.
    r"|googlesyndication|googleadservices|doubleclick|googleads|admob"
    r"|iadsdk|adsdk|advertising|adservices",
    re.I,
)

# Ad networks whose host is recognized by name even when their root domain is generic
# to its owner.
AD_HOST = re.compile(
    r"(?:^|[.-])(?:pagead\d*|ads?|adsense|admob|adservice|adservices|"
    r"ogads|gads|iadsdk|adnxs|syndication)(?:[.-]|$)",
    re.I,
)

# Security services installed on the device: blocking their service disables the
# protection they were installed to provide.
SECURITY_VENDORS = frozenset(
    {
        "norton.com", "symantec.com", "nortonlifelock.com", "mcafee.com",
        "kaspersky.com", "avast.com", "avg.com", "bitdefender.com",
        "eset.com", "malwarebytes.com",
    }
)

# Fraud detection and human verification: blocking them makes websites reject you.
ANTI_FRAUD = re.compile(
    r"datadome|fingerprintjs|(?:^|[.-])fpjs(?:[.-]|$)|perimeterx|px-cloud|"
    r"arkoselabs|funcaptcha|hcaptcha|recaptcha|castle\.io|shieldsquare|"
    r"incapsula|turnstile",
    re.I,
)


# Name prefixes indicating log transport or measurement, even when the domain belongs
# to the app's owner.
TELEMETRY_LABEL = re.compile(
    r"^(?:rt)?(?:log|logs|logging|applog|metric|metrics|stat|stats|telemetry|"
    r"beacon|track|tracking|report|reporting|collect|collector|ingest|"
    r"analytic|analytics|sentry|crash|eum|apm|rum|monitor|monitoring)(?:[0-9._-]|$)",
    re.I,
)


# Government services: national identity and official services. Blocking them prevents
# their owner from completing transactions, and they are not commercial tracking
# platforms. Those that are purely measurement are decided earlier by name.
GOVERNMENT_SERVICE = re.compile(r"\.gov(?:\.[a-z]{2})?$|\.gob\.|\.gouv\.|\.mil$", re.I)


# Catalog categories that are never a function of an app, whoever its owner is.
_AUDITED_COLLECTION_CATEGORIES = (
    TRACKING_CATEGORIES | _PURE_COLLECTION_CATEGORIES | frozenset({"device_integrity"})
)


def _base_domain(domain: str) -> str:
    labels = str(domain or "").strip(".").lower().split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else ""


def _is_ad_platform(domain: str) -> bool:
    base = _base_domain(domain)
    return bool(base and AD_PLATFORM_BASE.search(base))


def _vendor_families(bundles: tuple[str, ...]) -> tuple[str, ...]:
    joined = " ".join(bundles)
    families: list[str] = []
    for vendor, domains in VENDOR_DOMAIN_FAMILIES:
        if vendor.search(joined):
            families.extend(domains)
    return tuple(families)


def _first_party_for_caller(domain: str, bundles: tuple[str, ...]) -> bool:
    """Is this domain owned by the owner of one of the calling apps? By name or by vendor family."""
    base = _base_domain(domain)
    if not base:
        return False
    for family in _vendor_families(bundles):
        if base == family or base.endswith("." + family):
            return True
    root = base.split(".")[0]
    if len(root) < 4:
        return False
    for bundle in bundles:
        for token in re.split(r"[^a-z0-9]+", str(bundle).lower()):
            if len(token) >= 4 and (token in root or root in token):
                return True
    return False
def _squash(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(name).lower())


def trusted_app_caller(callers: tuple[str, ...]) -> str:
    """A caller you marked as trusted in Settings: nothing it calls is blocked, on the PC or the phone."""
    import user_exceptions

    return user_exceptions.trusted_app(callers)


def domain_function_role(
    domain: str, callers: tuple[str, ...] = ()
) -> tuple[str, str]:
    """Role of a domain for its callers: `function`, `additional` or `unknown`.

    `function` means blocking it would break what the app was installed for, so suggesting
    a block is forbidden. `additional` means it is extra to the function, so blocking it is
    what the app is meant to do. The order is deliberate: what is known to be extra is decided
    first, so a declared-purpose caller does not protect it — measurement domains that an
    attendance app calls are blocked in full.
    """
    name = str(domain or "").strip().strip(".").lower()
    if not name:
        return "function", "invalid domain name"
    clean_callers = tuple(str(item).strip() for item in callers if str(item).strip())
    trusted = trusted_app_caller(clean_callers)
    if trusted:
        return "function", f"called by an app you trust ({trusted}), and nothing it calls is blocked"

    if COLLECTOR_PATTERN.search(name):
        return "additional", "the hostname declares it is a collection endpoint"
    if TELEMETRY_LABEL.match(name.split(".", 1)[0]):
        # Being the app maker's own domain does not make it a function: `log22` on TikTok is
        # log transfer, not search or display, and blocking it stops nothing the user sees.
        return "additional", "the first label of the hostname indicates log transfer or measurement"
    if _is_ad_platform(name) or AD_HOST.search(name):
        return "additional", "ad platform or bidding domain"
    catalogued = verdict_for(name)
    if catalogued and str(catalogued.get("category", "")) in _AUDITED_COLLECTION_CATEGORIES:
        # The audited catalogue is more reliable than the "domain belongs to the app" heuristic:
        # device-integrity checks in a banking app are on its owner's domain, yet not part of its function.
        return "additional", "the audited catalogue classifies it as collection or checking, not function"
    if THIRD_PARTY_EXTRA.search(name):
        return "additional", "third-party service extra to the app's function"

    if ANTI_FRAUD.search(name):
        return "function", "fraud detection or user verification; blocking it rejects you as the user"
    if DOWNLOADABLE_CONTENT.search(name):
        return "function", "content download path or map for offline use"
    if CONTENT_DELIVERY_BASE.search(_base_domain(name)):
        return "function", "delivery path for images and files the app displays"
    if THIRD_PARTY_FUNCTIONAL.search(name):
        return "function", "service the app's operation depends on: registration, settings or authentication"
    if FEDERATED_LOGIN_OR_DELIVERY.search(name):
        return "function", "federated login or notification delivery path; blocking it stops you from using the app"

    base = _base_domain(name)
    if base in SECURITY_VENDORS:
        return "function", "service of an installed security app; blocking it disables the protection itself"
    if GOVERNMENT_SERVICE.search(name):
        return "function", "government or national ID service; blocking it prevents completing the transaction"

    if clean_callers and _first_party_for_caller(name, clean_callers):
        purpose = caller_purpose(clean_callers)
        if purpose:
            return "function", "the app owner's own domain serves its declared purpose"
        return "function", "the app owner's own domain that calls it, not a third party"

    return "unknown", ""
def functional_purpose_veto(
    domain: str, callers: tuple[str, ...] = ()
) -> tuple[bool, str]:
    """Would blocking this domain defeat the purpose the app was installed for?

    Returns (blocking is vetoed, reason). The verdict is purely local, and no model
    can overturn it, because its harm falls on the device owner, not on the tracker.
    What is not a function is not vetoed: a Google measurement domain called by an
    attendance app is blocked entirely, since it has nothing to do with preparation.
    """
    role, reason = domain_function_role(domain, callers)
    return role == "function", reason if role == "function" else ""


def ai_block_gate(
    domain: str, local_category: str = "", callers: tuple[str, ...] = ()
) -> tuple[bool, str]:
    """Does the local engine permit blocking a domain that a model marked red?

    The model's verdict alone is not enough to propose blocking: the domain's local
    category may be a runtime path, and the host name may indicate authentication,
    payment or updates, or the domain may be the app's own function rather than a
    violation of it. The agreed rule of this project is that blocking must not break
    the app, so the veto takes precedence over blocking whenever they conflict.
    Returns (allowed, reason for the veto).
    """
    name = (domain or "").strip().strip(".").lower()
    if not name:
        return False, "invalid domain name"
    vetoed, purpose_reason = functional_purpose_veto(name, callers)
    if vetoed:
        return False, purpose_reason
    curated = verdict_for(name)
    if curated and not is_block_safe(name, str(curated.get("category", ""))):
        return False, "the reviewed catalog classifies it as a functional path"
    if local_category in _GUESSED_CATEGORIES and COLLECTOR_PATTERN.search(name):
        # "operational service" is a guess from the name (cdn or api, confidence 52), and the
        # collector list is reviewed: the category used to take precedence, which left Instabug,
        # Sprig and Datadog open on mobile even though they were in the list.
        return True, ""
    if local_category in _NEVER_BLOCK_CATEGORIES:
        return False, "the local category is a runtime path that must not be blocked"
    if local_category in _PURE_COLLECTION_CATEGORIES:
        # A pure collection category confirmed by review: nothing
        # at runtime depends on it, whatever the host name begins with.
        return True, ""
    if COLLECTOR_PATTERN.search(name):
        return True, ""
    if OPERATIONAL_PATTERN.match(name.split(".", 1)[0]):
        return False, "the host name indicates a runtime path (authentication, payment or updates)"
    return True, ""


def is_block_safe(domain: str, category: str) -> bool:
    """Can this domain be blocked without breaking the app's function?"""
    name = (domain or "").strip().strip(".").lower()
    if category in _GUESSED_CATEGORIES and COLLECTOR_PATTERN.search(name):
        return True  # the reviewed collector list takes precedence over the category guessed from the name, as in ai_block_gate
    if category in _NEVER_BLOCK_CATEGORIES:
        return False
    if category in _PURE_COLLECTION_CATEGORIES:
        return True
    if COLLECTOR_PATTERN.search(name):
        return True
    first_label = name.split(".", 1)[0]
    if OPERATIONAL_PATTERN.match(first_label):
        return False
    return category in TRACKING_CATEGORIES


# ---------------------------------------------------------------------------
# Location: judged by the function of the requesting app
# ---------------------------------------------------------------------------
# A location request is legitimate when it is the app's function: attendance logging, maps,
# delivery, weather, tracking a lost device. It is not legitimate when it comes from a bank,
# a services app, a social network or a game, because the service works without location.

LOCATION_JUSTIFIED_APPS = re.compile(
    r"huduri|availo|hather|attendance|hudur|maps?\b|khareta|weather|"
    r"apple\.weather|find(?:my)?|fmf|hungerstation|keeta|meituan|jahez|careem|"
    r"uber|talabat|noon|aramex|smsa|health|fitness|sport|forzafootball|"
    r"livescore|com\.apple\.Maps|com\.google\.Maps|shortcuts",
    re.I,
)

LOCATION_UNJUSTIFIED_APPS = re.compile(
    r"alinma|sabb|\bsab\b|derayah|sahm|vcfc|d360|barraq|tabby|riyad|rajhi|"
    r"\bsnb\b|\banb\b|\bgib\b|meem|paypal|bank|absher|tawakkalna|nafath|"
    r"myid|madrasati|t4edu|mobily|\bstc\b|zain|imdb|tweetie|twitter|musically|"
    r"tiktok|snapchat|whatsapp|telegram|puzzle|woodenblock|symantec|norton",
    re.I,
)
def location_findings(
    category: str,
    contexts: list[str] | tuple[str, ...] | None,
) -> dict[str, list[str]]:
    """Classify apps that requested a location point as justified or unjustified.

    Returns an empty dict if the category is not location-related. The result is shown
    at the app level, not the domain level, because iOS routes all apps to the same Apple
    domain; blocking the domain would disable location for a presence app and for Maps too.
    """
    if category != "location":
        return {}
    justified: list[str] = []
    unjustified: list[str] = []
    for item in contexts or []:
        name = str(item).strip()
        if not name:
            continue
        if LOCATION_JUSTIFIED_APPS.search(name):
            if name not in justified:
                justified.append(name)
        elif LOCATION_UNJUSTIFIED_APPS.search(name):
            if name not in unjustified:
                unjustified.append(name)
    if not justified and not unjustified:
        return {}
    return {"justified": justified, "unjustified": unjustified}
