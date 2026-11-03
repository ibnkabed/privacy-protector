from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import os
import queue
import re
import socket
import ssl
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from domain_verdicts import (
    ai_block_gate,
    escalate_for_context,
    is_block_safe,
    location_findings,
    verdict_for,
)


ENGINE_VERSION = 3
CLASSIFICATION_RULESET_VERSION = 10
BACKGROUND_ANALYSIS_WORKERS = 2
# The classification file is rewritten whole. Observations therefore mark it
# dirty and a background thread persists it, instead of every DNS answer
# waiting for a multi-megabyte write.
PERSIST_FLUSH_SECONDS = 5.0
STARTUP_CATCHUP_LIMIT = 32
# A telemetry-patterned domain contacted by at least this many distinct app
# bundles is treated as a third-party SDK rather than a first-party service.
SHARED_SDK_MIN_APPS = 5
RISK_ORDER = {"unclassified": -1, "green": 0, "orange": 1, "red": 2}
RISK_LABELS = {
    "unclassified": "new — awaiting study",
    "green": "green — functional and does not infringe on privacy",
    "orange": "orange — suspicious, warrants monitoring without certainty of a privacy violation",
    "red": "red — tracking or a clear privacy infringement",
}
STAGE_LABELS = {"new": "new", "preliminary": "preliminary", "studied": "studied"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _observation_iso(value: Any) -> str:
    clean = str(value or "").strip()
    if not clean:
        return ""
    try:
        parsed = datetime.fromisoformat(clean.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone().isoformat(timespec="seconds")
    except ValueError:
        return ""


def _latest_observation(current: Any, candidate: Any) -> str:
    current_iso = _observation_iso(current)
    candidate_iso = _observation_iso(candidate)
    if not candidate_iso:
        return current_iso
    if not current_iso:
        return candidate_iso
    return max(current_iso, candidate_iso, key=lambda value: datetime.fromisoformat(value))


def _normalize_domain(value: str) -> str:
    clean = str(value or "").strip().lower().rstrip(".")
    if not clean or len(clean) > 253:
        return ""
    try:
        clean = clean.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    labels = clean.split(".")
    if len(labels) < 2 or any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not re.fullmatch(r"(?:[a-z0-9-]+|_[a-z0-9-]+)", label)
        for label in labels
    ):
        return ""
    try:
        ipaddress.ip_address(clean)
        return ""
    except ValueError:
        return clean
def _bounded(value: Any, maximum: int = 500) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()[:maximum]


def _catalog_entry(
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


CURATED_DOMAIN_CATALOG: dict[str, dict[str, Any]] = {
    "smart.alinma.com": _catalog_entry(
        "red",
        "device_integrity",
        "Device check and developer mode",
        "Interface for checking the device environment related to banking app protection.",
        "Locally linked to GIBMobileSDK signals, developer mode checks, and device status; any developer mode check is classified as red.",
        "https://www.group-ib.com/products/fraud-protection/",
        developer_check=True,
        device_data=True,
    ),
    "alinma.api.dataroid.com": _catalog_entry(
        "red",
        "behavior_analytics",
        "User behavior analytics",
        "Aggregation of session events and interactions via the Dataroid platform.",
        "Dataroid documentation mentions tracking clicks, views, session details, and device information.",
        "https://www.dataroid.com/unified-digital-data/",
        device_data=True,
    ),
    "cdn-alinma.dataroid.com": _catalog_entry(
        "green",
        "analytics_configuration",
        "Analytics service initialization",
        "File host and configuration for the Dataroid service, not a standalone aggregation point.",
        "Its apparent function is distributing configuration files; no attribution of sending private data without evidence of an actual request.",
        "https://www.dataroid.com/unified-digital-data/",
    ),
    "rum.alinma.com": _catalog_entry(
        "red",
        "real_user_monitoring",
        "Session and interaction monitoring",
        "Real User Monitoring interface linked to session, interaction, and performance measurement.",
        "RUM documentation clarifies the ability to record sessions, interactions, device characteristics, and approximate location.",
        "https://docs.dynatrace.com/docs/observe/digital-experience/rum/concepts/data-model",
        device_data=True,
    ),
    "api-gw.alinma.com": _catalog_entry(
        "green", "core_api", "Core banking service", "Primary API gateway for the Alinma app.",
        "Hosted on the bank's domain and dedicated to core app operations; the hostname provides no indication of tracking or device checking.",
    ),
    "alinma.com": _catalog_entry(
        "green", "first_party", "First-party service", "Alinma Bank's primary domain.",
        "A first-party domain; its connection alone is not evidence of tracking or privacy violation.",
    ),
    "cookie.privacy.alinma.com": _catalog_entry(
        "green", "consent", "Consent and privacy management", "Cookie settings and consent service.",
        "The hostname and its function are related to managing privacy preferences, not collecting device data.",
    ),
    "ad.doubleclick.net": _catalog_entry(
        "red", "advertising", "Advertising and conversion tracking", "Google advertising host and conversion measurement.",
        "Advertising service linked to audience and conversion measurement.", "https://business.safety.google/adsservices/",
        device_data=True,
    ),
    "googleads.g.doubleclick.net": _catalog_entry(
        "red", "advertising", "Advertising and conversion tracking", "Google Ads host for advertising and conversion measurement.",
        "The advertising function and conversion measurement make it privacy-sensitive.", "https://business.safety.google/adsservices/",
        device_data=True,
    ),
    "aax-eu.amazon-adsystem.com": _catalog_entry(
        "red", "advertising", "Advertising and interests", "Amazon Ads service for delivering and measuring ads.",
        "The ads-system domain specializes in advertising and audience measurement.", "https://advertising.amazon.com/",
        device_data=True,
    ),
    "amazon-adsystem.com": _catalog_entry(
        "red", "advertising", "Advertising and interests", "The primary domain for the Amazon Ads ecosystem.",
        "An advertising system that may use audience signals and interests.", "https://advertising.amazon.com/",
        device_data=True,
    ),
    "dpm.demdex.net": _catalog_entry(
        "red", "audience_tracking", "Audience definition and tracking", "Adobe Audience Manager endpoint for collecting audience signals and identifiers.",
        "Adobe documentation mentions UUID, synchronization, hashing, and user signal collection.",
        "https://experienceleague.adobe.com/en/docs/audience-manager/user-guide/faqs/faq-data-collection",
        device_data=True,
    ),
    "gslb-2.demdex.net": _catalog_entry(
        "red", "audience_tracking", "Audience definition and tracking", "Routing structure for the Adobe Audience Manager platform.",
        "Direct link to the demdex system dedicated to collecting audience signals and synchronizing identifiers.",
        "https://experienceleague.adobe.com/en/docs/core-services/interface/data-collection/cookies/audience-manager",
        device_data=True,
    ),
    "analytics.adjust.com": _catalog_entry(
        "red", "attribution", "Installation attribution and tracking", "Adjust service for measuring app installs and campaign attribution.",
        "Attribution links app opens or installs to campaigns and measurement identifiers.", "https://www.adjust.com/product/measurement/",
        device_data=True,
    ),
    "ksrfpc.launches.appsflyersdk.com": _catalog_entry(
        "red", "attribution", "App launch attribution", "AppsFlyer endpoint for measuring app launches and campaign attribution.",
        "The name 'launches' and documented AppsFlyer functionality indicate launch recording and attribution.",
        "https://support.appsflyer.com/hc/en-us/categories/201114756-SDK-integration",
        device_data=True,
    ),
    "ksrfpc.skadsdkless.appsflyersdk.com": _catalog_entry(
        "red", "attribution", "Ad attribution", "AppsFlyer endpoint for campaign attribution without the full SKAdNetwork SDK.",
        "The service is dedicated to ad attribution and measuring the source of installation or launch.",
        "https://support.appsflyer.com/hc/en-us/categories/201114756-SDK-integration",
        device_data=True,
    ),
    "api.rudderstack.com": _catalog_entry(
        "red", "behavior_analytics", "Event analytics", "RudderStack interface for collecting app usage events.",
        "Customer Data Platform collects customer events and routes them to analytical destinations.", "https://www.rudderstack.com/docs/",
        device_data=True,
    ),
    "app-measurement.com": _catalog_entry(
        "red", "behavior_analytics", "App usage measurement", "Google Analytics for Firebase endpoint for measuring engagement.",
        "Collects app usage events and links them to session and audience metrics.", "https://firebase.google.com/docs/analytics",
        device_data=True,
    ),
    "app-analytics-services.com": _catalog_entry(
        "red", "behavior_analytics", "Usage analytics", "App usage analytics service.",
        "The observed host name and function are dedicated to usage analytics.", device_data=True,
    ),
    "analytics.tiktok.com": _catalog_entry(
        "red", "behavior_analytics", "TikTok Analytics", "Collecting metrics and usage events for TikTok.",
        "Explicit 'analytics' host for a social and advertising platform.", "https://www.tiktok.com/legal/page/row/privacy-policy/en",
        device_data=True,
    ),
    "analytics-ipv6.tiktokw.us": _catalog_entry(
        "red", "behavior_analytics", "TikTok Analytics", "IPv6 endpoint for TikTok analytics.",
        "Explicit 'analytics' host for collecting metrics.", "https://www.tiktok.com/legal/page/row/privacy-policy/en",
        device_data=True,
    ),
    "analytics.twitter.com": _catalog_entry(
        "red", "behavior_analytics", "X Analytics", "Usage measurement and analytics related to the X platform.",
        "Explicit 'analytics' host.", "https://x.com/en/privacy", device_data=True,
    ),
    "analytics-prod.tf.ff.avast.com": _catalog_entry(
        "red", "behavior_analytics", "Security product analytics", "Avast/Norton product usage measurement.",
        "Explicit 'analytics' host that sends product metrics.", device_data=True,
    ),
    "analytics.avcdn.net": _catalog_entry(
        "red", "behavior_analytics", "Security product analytics", "Analytics endpoint associated with Avast/Norton products.",
        "Explicit 'analytics' host.", device_data=True,
    ),
    "c.clarity.ms": _catalog_entry(
        "red", "session_analytics", "Session analysis and recording", "Microsoft Clarity endpoint for session and interaction analytics.",
        "Clarity's documentation describes collecting user interactions and session recording, depending on configuration.",
        "https://learn.microsoft.com/en-us/clarity/mobile-sdk/sdk-data-capture-rules", device_data=True,
    ),
    "e.clarity.ms": _catalog_entry(
        "red", "session_analytics", "Session analysis and recording", "Microsoft Clarity event submission endpoint.",
        "Tied to collecting analytics and session interactions.",
        "https://learn.microsoft.com/en-us/clarity/mobile-sdk/sdk-data-capture-rules", device_data=True,
    ),
    "www.clarity.ms": _catalog_entry(
        "red", "session_analytics", "Session analysis and recording", "Microsoft Clarity interface for user behavior analytics.",
        "Tied to the session recording and interaction analytics platform.",
        "https://learn.microsoft.com/en-us/clarity/mobile-sdk/sdk-data-capture-rules", device_data=True,
    ),
    "in.appcenter.ms": _catalog_entry(
        "orange", "crash_diagnostics", "App Center Diagnostics", "Microsoft App Center endpoint for analytics and crashes during development and runtime.",
        "Operational diagnostic data with stability value; monitored, not blocked, under the balanced review.",
        "https://learn.microsoft.com/en-us/appcenter/", device_data=True,
    ),
    "ca.iadsdk.apple.com": _catalog_entry(
        "red", "advertising", "Apple Ads", "Apple iAd endpoint for ad measurement or delivery.",
        "Explicit advertising SDK host.", device_data=True,
    ),
    "iadsdk.apple.com": _catalog_entry(
        "red", "advertising", "Apple Ads", "Apple iAd endpoint for ad measurement or delivery.",
        "Explicit advertising SDK host.", device_data=True,
    ),
    "crashlyticsreports-pa.googleapis.com": _catalog_entry(
        "orange", "diagnostics", "Device crash reports", "Uploading crash reports and diagnostic information to Firebase Crashlytics.",
        "The service collects crashes, exceptions and technical properties to diagnose stability; not by itself a proven misuse of a sensitive permission.",
        "https://firebase.google.com/docs/crashlytics", device_data=True,
    ),
    "firebaselogging-pa.googleapis.com": _catalog_entry(
        "red", "behavior_analytics", "Firebase Remote Logs", "Uploading app logs and events to Google servers.",
        "Dedicated logging host for uploading logs and analytics, not a core function; many apps contacting it indicates a measurement SDK.",
        "https://firebase.google.com/", device_data=True,
    ),
    "247bc-1324b.api.pushwoosh.com": _catalog_entry(
        "red", "engagement_tracking", "Notifications and interaction tracking", "Pushwoosh interface for device registration, notifications, and interaction events.",
        "Pushwoosh's documentation lists HWID, IDFV, the push token, app opens, events and attributes.",
        "https://docs.pushwoosh.com/developer/pushwoosh-knowledge-hub/device-identifiers", device_data=True,
    ),
    "ha-device.pushwoosh.com": _catalog_entry(
        "red", "engagement_tracking", "Device identification and notifications", "Pushwoosh host associated with device registration and notifications.",
        "Pushwoosh uses the device ID and push token and may log app opens and events.",
        "https://docs.pushwoosh.com/developer/api-reference/api-methods-reference-index", device_data=True,
    ),
    "accounts.google.com": _catalog_entry(
        "green", "authentication", "Sign-in", "Google Account authentication service.",
        "A core sign-in function, not by itself evidence of device tracking.", "https://developers.google.com/identity",
    ),
    "oauth2.googleapis.com": _catalog_entry(
        "green", "authentication", "OAuth Authentication", "Google OAuth token interface.",
        "Basic sign-in and authorization service.", "https://developers.google.com/identity/protocols/oauth2",
    ),
    "mask.apple-dns.net": _catalog_entry(
        "green", "privacy_protection", "DNS and Private Relay Protection", "Apple architecture for protecting user queries and browsing.",
        "Falls under Relay services designed to prevent linking user identity to websites.", "https://support.apple.com/en-us/102602",
    ),
    "gateway.icloud.com": _catalog_entry(
        "green", "privacy_protection", "iCloud Gateway", "Apple gateway for iCloud services and protected connectivity.",
        "A system service from Apple; no evidence of tracking or developer pattern analysis from the hostname.", "https://support.apple.com/en-us/102602",
    ),
    "ohttp-relay-safebrowsing-chrome.google.fastly-edge.com": _catalog_entry(
        "green", "security", "Browsing Protection", "OHTTP proxy for Chrome's Safe Browsing service.",
        "The proxy isolates safety check requests from the original site address and serves a protective purpose.",
        "https://security.googleblog.com/2024/09/enhanced-protection-for-chrome.html",
    ),
    "u.expo.dev": _catalog_entry(
        "green", "app_updates", "App Updates", "Expo Updates service for downloading app updates and files.",
        "An update distribution architecture, not a proven tracking point.", "https://docs.expo.dev/eas-update/introduction/",
    ),
    "gspe79-cdn.g.aaplimg.com": _catalog_entry(
        "green", "infrastructure", "Apple Files", "Apple file distribution network.",
        "A CDN host for files; does not inherently prove access to device data.",
    ),
    "gspe79-ssl.ls.apple.com": _catalog_entry(
        "red", "location", "Location and Maps Services", "Apple Location Services/Maps endpoint.",
        "The host is associated with location services; evidence becomes critical when linked to an app with denied location permissions.", device_data=True,
    ),
    "guzzoni-apple-com.v.aaplimg.com": _catalog_entry(
        "green", "infrastructure", "Siri Files", "File distribution network associated with Siri.",
        "A file host, not a proven point for transmitting audio or device data.",
    ),
    "guzzoni.apple.com": _catalog_entry(
        "orange", "assistant", "Siri Service", "System interface for Siri assistant that may handle user input when activated.",
        "A system function that may transmit operational data or assistant requests, but DNS presence alone does not prove permission violation.",
        "https://www.apple.com/legal/privacy/data/en/ask-siri-dictation/", device_data=True,
    ),
    "mtalk.google.com": _catalog_entry(
        "orange", "push", "notification channel", "Google's persistent channel for delivering messages and notifications.",
        "Uses operational device/app tokens for delivery; does not prove infringement on location, traffic, or prohibited tracking.", device_data=True,
    ),
    "android.clients.google.com": _catalog_entry(
        "orange", "device_service", "Google Device Service", "Google client service for managing registration or syncing device components.",
        "May handle system information and operational identifiers; no explicit evidence of privacy violation from the host alone.", device_data=True,
    ),
    "clients.l.google.com": _catalog_entry(
        "orange", "device_service", "Google Client Service", "Support and synchronization service for Google clients.",
        "May use operational device properties; exact purpose is determined by context and application.", device_data=True,
    ),
    "clients3.google.com": _catalog_entry(
        "orange", "device_service", "Google Client Service", "System service for Google and Chrome clients.",
        "May handle updates, connection checks, and operational properties, without explicit evidence of infringement.", device_data=True,
    ),
    "optimizationguide-pa.googleapis.com": _catalog_entry(
        "orange", "personalization", "Improve Chrome experience", "Chrome Optimization Guide interface to provide models or optimization hints.",
        "Optimization service may depend on browser and device context, and does not prove access to restricted sensitive permissions.", device_data=True,
    ),
    "www.google.com": _catalog_entry(
        "green", "first_party", "General Google service", "Multi-purpose general Google domain.",
        "The general domain cannot be considered tracking merely by its appearance; path and context are required to determine the exact function.",
    ),
    "bing.com": _catalog_entry(
        "green", "search", "Web search", "General Bing search service.",
        "Direct search function; the general host alone does not prove tracking within another app.",
    ),
    "www.googletagmanager.com": _catalog_entry(
        "red", "tracking_loader", "Load tracking tags", "Google Tag Manager service for loading measurement and tracking tags.",
        "The primary purpose is running measurement tags and may enable multiple tracking services.", "https://developers.google.com/tag-platform/tag-manager",
        device_data=True,
    ),
    "www.facebook.com": _catalog_entry(
        "orange", "social_service", "Multi-purpose social service", "General Facebook domain; usage may be direct or embedded.",
        "The general host is insufficient to prove tracking; classified as orange until SDK or tracking pixel context is proven.", device_data=True,
    ),
    "linkedin.com": _catalog_entry(
        "orange", "social_service", "Multi-purpose social service", "Multi-purpose general LinkedIn domain.",
        "May be direct access or a social component; the general host alone does not prove a violation.", device_data=True,
    ),
    "snapchat.com": _catalog_entry(
        "orange", "social_service", "Multi-purpose social service", "Multi-purpose general Snapchat domain.",
        "Context is required to distinguish between direct use and measurement SDK.", device_data=True,
    ),
    "twitter.com": _catalog_entry(
        "orange", "social_service", "Multi-purpose social service", "Multi-purpose general X/Twitter domain.",
        "The general host alone does not prove tracking.", device_data=True,
    ),
    "t.co": _catalog_entry(
        "orange", "link_redirect", "Shortening and redirection", "Link shortening service affiliated with the X platform.",
        "Redirection may log link opens but does not prove access to sensitive permissions.", device_data=True,
    ),
}

# Reviewed service-role mappings for hosts already present in the local history.
# They intentionally classify the host role only; they do not claim visibility
# into an encrypted path or payload.
for _domain in (
    "apple.com", "www.apple.com", "p39-buy.itunes.apple.com",
    "mmx-ds.cdn.whatsapp.net", "media-hbe1-1.cdn.whatsapp.net", "api.whatsapp.net",
    "g.whatsapp.net", "sshr.moe.gov.sa", "passwordsleakcheck-pa.googleapis.com",
    "configuration.g.aaplimg.com", "quota.fe2.apple-dns.net", "p186-quota.icloud.com",
    "ocsp2.g.aaplimg.com", "ocsp2.apple.com", "bag-cdn.itunes-apple.com.akadns.net",
    "clientservices.googleapis.com", "t0.gstatic.com", "safebrowsing.googleapis.com",
    "a1931.dscgi3.akamai.net", "e673.dsce9.akamaiedge.net", "e6858.dsce9.akamaiedge.net",
    "a1914.dscapi9.akamai.net", "a2030.dscapi9.akamai.net", "a2047.dscapi9.akamai.net",
    "e3528.dscg.akamaiedge.net", "e17437.dsct.akamaiedge.net", "www.googleapis.com",
    "play.google.com", "cdn-content.ampproject.org", "cdn.ampproject.org",
    "googlehosted.l.googleusercontent.com", "yt3.ggpht.com", "lh3.googleusercontent.com",
    "securitydomain-pa.googleapis.com", "accountcapabilities-pa.googleapis.com",
    "encrypted-tbn0.gstatic.com", "update.googleapis.com", "www.gstatic.com",
    "play.googleapis.com", "cdn.tawakkalna.sa.queniuaa.com", "cdn.tawakkalna.sa",
    "snf3.nic.gov.sa", "snf3.gslb.nic.gov.sa", "configuration-lb.ls-apple.com.akadns.net",
    "get-bx.g.aaplimg.com", "www3.l.google.com", "safebrowsing.g.aaplimg.com",
    "token.safebrowsing.apple", "amp-api-edge-cdn-lb.itunes-apple.com.akadns.net",
    "captive.g.aaplimg.com", "xp.g.aaplimg.com", "app-site-association.cdn-apple.com",
    "p39-buy-as.itunes.v.aaplimg.com", "mzstorekit.itunes.apple.com",
    "mzstorekit.g.aaplimg.com", "init.itunes.apple.com", "download.apple.map.fastly.net",
    "iosapps.itunes.apple.com", "se-edge.itunes.apple.com", "musicstatus.itunes.apple.com",
    "fpinit-itunes.g.aaplimg.com", "cdn-h3.g.aaplimg.com", "init.gc.apple.com",
    "setup.icloud.com", "entitlements.itunes.apple.com", "amp-api-search-edge.apps.apple.com",
    "amp-api.apps.apple.com", "amp-api-edge-lb.itunes-apple.com.akadns.net",
    "is1-ssl.mzstatic.com", "pd.itunes.apple.com", "apps.mzstatic.com",
    "silverbullet-external-ats.itunes.apple.com", "api-edge.apps.apple.com",
    "api.apps.apple.com", "apps.itunes-nocookie.com", "sf-api-token-service.itunes.apple.com",
    "fpinit.itunes.apple.com", "applepay-tns.prod.bp.acloud.gemalto.com",
    "applepay-tns.cbp.gemalto.com", "prmb.sabb.com", "www.gslb.sabb.com",
    "www.sab.com", "app-cs-prod.gslb.sabb.com", "app-cs-prod.sab.com",
    "ocsp.digicert.com", "eip-terr-eu.cdp1.digicert.com.akahost.net",
    "dualstack.video.twitter.map.fastly.net", "dualstack.twimg.twitter.map.fastly.net",
    "dynamic.x.com.cdn.cloudflare.net", "a708.dsct.akamai.net",
    "block.dns-selftest.invalid", "monitor.dns-selftest.invalid", "allow.dns-selftest.invalid",
    "gateway.fe2.apple-dns.net",
):
    CURATED_DOMAIN_CATALOG.setdefault(
        _domain,
        _catalog_entry(
            "green", "infrastructure", "Operational or trusted service",
            "Functional host for authentication, files, store, protection, or core service of the entity.",
            "Host role is operational based on the entity and name; no independent evidence of sensitive device data inspection.",
        ),
    )

for _domain, _label, _summary, _source in (
    ("peoplestack-pa.googleapis.com", "Contacts and profile", "Google service for people and profile data.", "https://developers.google.com/people"),
    ("people-pa.googleapis.com", "Contacts and profile", "Google People API for people and contact data.", "https://developers.google.com/people"),
    ("history.google.com", "Activity history", "Service linked to Google activity history.", "https://myactivity.google.com/"),
    ("discover-pa.googleapis.com", "Content personalization", "Google Discover service for content personalization.", "https://support.google.com/websearch/answer/2819496"),
    ("growth-pa.googleapis.com", "Growth measurement and engagement", "Measurement or personalization API linked to product growth usage.", ""),
    ("ogads-pa.clients6.google.com", "Ads and measurement", "Google API linked to ads and measurement.", "https://business.safety.google/adsservices/"),
    ("www.googleadservices.com", "Ads and measurement", "Google Ads service and conversion measurement.", "https://business.safety.google/adsservices/"),
    ("pubads.g.doubleclick.net", "Ads and tracking", "DoubleClick service for delivering and measuring ads.", "https://business.safety.google/adsservices/"),
    ("odf.app-ads-services.com", "Ad attribution", "Measurement and attribution service for app ads.", ""),
    ("tr.iadsdk.apple.com", "Apple Ads", "Tracking or measurement endpoint belonging to the iAd SDK.", ""),
    ("stats.norton.com.trafficmanager.net", "Protection product statistics", "Usage statistics endpoint linked to a Norton product.", ""),
    ("stats.norton.com", "Protection product statistics", "Usage statistics endpoint linked to a Norton product.", ""),
    ("api.mixpanel.com", "User behavior analytics", "Mixpanel API for collecting product events and analytics.", "https://docs.mixpanel.com/docs/tracking-methods/sdks"),
    ("api.eu.amplitude.com", "User behavior analytics", "Amplitude API for collecting product events and analytics.", "https://amplitude.com/docs/sdks/analytics"),
    ("sdk-02.moengage.com", "User engagement and tracking", "MoEngage SDK for events, engagement, and notifications.", "https://developers.moengage.com/"),
    ("eum.sabb.com", "User experience monitoring", "End User Monitoring endpoint for recording performance and interaction.", ""),
    ("euc1-wps-prod.apple.com", "Location service", "Apple service that assists with Wi-Fi-based location.", ""),
    ("wps.v.aaplimg.com", "Location service", "Files and configuration for Apple's location assistance service.", ""),
    ("iphone-ld.g.aaplimg.com", "Location service", "Apple data assisting with location determination.", ""),
    ("iphone-ld.apple.com", "Location service", "Apple endpoint for location services.", ""),
    ("fmf.fe2.apple-dns.net", "Find device and people", "Find My service linked to location.", "https://support.apple.com/find-my"),
    ("p69-fmf.icloud.com", "Find device and people", "iCloud Find My service linked to location.", "https://support.apple.com/find-my"),
):
    CURATED_DOMAIN_CATALOG.setdefault(
        _domain,
        _catalog_entry(
            "red", "privacy_data", _label, _summary,
            "The host function involves tracking, logging, advertising, location, or user engagement; therefore it is classified red.",
            _source, device_data=True,
        ),
    )

for _domain, _risk, _label, _summary in (
    ("weatherkit.apple.com.akadns.net", "orange", "WeatherKit infrastructure", "Routing target for Apple's WeatherKit service that may be linked to a weather request based on a location the app specifies."),
    ("fpinit-apac-n.edge-itunes-apple.com.akadns.net", "green", "Apple store initialization", "CDN target for initializing Apple store services in the Asia-Pacific region."),
    ("bag-cdn-lb.itunes-apple.com.akadns.net", "green", "Apple store initialization", "CDN target for configuration files of Apple store services."),
    ("h3.apis.apple.map.fastly.net", "red", "Map and location APIs", "Fastly target for Apple Maps services that may handle location-related requests."),
    ("mue1-ncs-ds-prod-pip-green-stack-std.eastus.cloudapp.azure.com", "green", "Intermediate cloud infrastructure", "Generic Azure routing target; the certificate name mismatch confirms it is an infrastructure target, not a direct account interface."),
):
    CURATED_DOMAIN_CATALOG.setdefault(
        _domain,
        _catalog_entry(
            _risk,
            "location" if _risk == "red" else "device_operational" if _risk == "orange" else "infrastructure",
            _label,
            _summary,
            "Classified from hosting relationship and service name; encrypted paths or contents are not inspected.",
            device_data=_risk != "green",
        ),
    )
for _domain, _label, _summary, _source in (
    ("content-autofill.googleapis.com", "Autofill", "Operational service for autofill suggestions and data.", ""),
    ("clients4.google.com", "Google Client Service", "Operational service for Google and Chrome clients.", ""),
    ("iphone-ld.g.aaplimg.com", "Location service", "Operational data for location services.", ""),
    ("api.revenuecat.com", "Subscriptions and User ID", "RevenueCat service for subscription status, purchases, and app user ID.", "https://www.revenuecat.com/docs/customers/user-ids"),
    ("friend.gc.apple.com", "Game Center Friends", "Social service for Game Center contacts and friends.", ""),
    ("weatherkit.apple.com", "Location-based weather", "WeatherKit API which may receive coordinates determined by the app.", "https://developer.apple.com/weatherkit/"),
    ("firebaseinstallations.googleapis.com", "Installation ID", "Operational Firebase Installation ID service.", "https://firebase.google.com/docs/projects/manage-installations"),
    ("device-provisioning.googleapis.com", "Device Setup", "Google service for setting up or registering the device.", ""),
    ("o2-ds.norton.com", "Protection and Diagnostics Service", "Operational service for Norton products that may use technical device information.", ""),
):
    CURATED_DOMAIN_CATALOG.setdefault(
        _domain,
        _catalog_entry(
            "orange", "device_operational", _label, _summary,
            "The service handles identifiers, operational properties, or functional content, without local evidence of sensitive permission abuse.",
            _source, device_data=True,
        ),
    )


RED_PATTERN = re.compile(
    r"(?:analytics|measurement|tracker|tracking|doubleclick|adsystem|appsflyer|adjust|"
    r"rudderstack|clarity|demdex|dataroid|tagmanager|attribution|devicecheck|appattest|"
    r"developer.?mode|jailbreak|root.?check|integrity|gibmobile|location|motion|fitness|health|"
    r"(?:^|[._-])(?:ad|ads|beacon|pixel|track)(?:[._-]|$)|adserver|adtraffic|"
    r"googlesyndication|unityads|vungle|fyber|smadex|rubiconproject|pubmatic|inmobi|"
    r"moloco|bidease|criteo|liftoff|chartboost|smaato)",
    re.IGNORECASE,
)
ORANGE_PATTERN = re.compile(
    r"(?:crash|logging|diagnostic|telemetry|performance|push|messaging|notification|"
    r"device|installation|instance|\biid\b|sentry|appcenter|optimization|assistant|siri)",
    re.IGNORECASE,
)
GREEN_PATTERN = re.compile(
    r"(?:auth|oauth|login|api|gateway|cdn|asset|static|font|image|privacy|relay|"
    r"safebrowsing|cookie|account|update)",
    re.IGNORECASE,
)


# Reviewed provider families whose public documentation identifies the endpoint
# purpose.  Keep these narrower than general keyword matching: a provider may
# host both functional assets and event-ingestion endpoints.
CURATED_DOMAIN_FAMILIES: tuple[tuple[re.Pattern[str], dict[str, Any]], ...] = (
    (
        re.compile(r"^(?:api(?:2|3)?|api\.(?:eu|lab))\.amplitude\.com$", re.I),
        _catalog_entry(
            "red",
            "behavior_analytics",
            "User behavior analytics",
            "Amplitude event input interface associated with the user, device, and session.",
            "Amplitude documentation defines these interfaces as entry points for usage events and user or device identifiers.",
            "https://amplitude.com/docs/apis/analytics/http-v2",
            device_data=True,
        ),
    ),
    (
        re.compile(r"^api\d*\.branch\.io$", re.I),
        _catalog_entry(
            "red",
            "attribution",
            "Event Attribution and Tracking",
            "Branch interface for attributing installs and conversions, and tracking app events.",
            "Branch documentation mentions event tracking and user or device identifiers required for attribution.",
            "https://help.branch.io/developer-hub/docs/track-branch-events",
            device_data=True,
        ),
    ),
    (
        re.compile(r"(?:^|\.)awstrack\.me$", re.I),
        _catalog_entry(
            "red",
            "email_tracking",
            "Link Open and Click Tracking",
            "Domain for tracking email opens and link clicks in Amazon SES.",
            "AWS reference explicitly names awstrack.me as the domain for open and click tracking.",
            "https://docs.aws.amazon.com/general/latest/gr/ses.html",
            device_data=True,
        ),
    ),
    (
        re.compile(r"(?:^|\.)googleadservices\.com$", re.I),
        _catalog_entry(
            "red",
            "advertising",
            "Ads and conversion tracking",
            "Google Ads service for measuring conversions and retargeting.",
            "Google documentation links googleadservices.com requests to conversion measurement and retargeting.",
            "https://support.google.com/tagassistant/answer/2954407",
            device_data=True,
        ),
    ),
    (
        re.compile(r"^dynatrace\.", re.I),
        _catalog_entry(
            "red",
            "real_user_monitoring",
            "User Experience and Behavior Monitoring",
            "Dynatrace Real User Monitoring endpoint for capturing sessions and user events.",
            "Dynatrace documentation explains the aggregation of user events, sessions, and browser identifiers in RUM.",
            "https://docs.dynatrace.com/docs/observe/digital-experience/rum/web-frontends/concepts/user-sessions-web",
            device_data=True,
        ),
    ),
    (
        re.compile(r"(?:^|\.)track\.smaato\.net$", re.I),
        _catalog_entry(
            "red",
            "advertising_tracking",
            "Ad Tracking",
            "Smaato service for logging impressions, clicks, and ad auction events.",
            "Smaato documentation defines tracking as recording user data and events for targeting and advertising.",
            "https://developers.smaato.com/publishers/glossary/",
            device_data=True,
        ),
    ),
    (
        re.compile(r"(?:^|\.)(?:advertising\.amazon\.dev|advertising\.a2z\.com)$", re.I),
        _catalog_entry(
            "red",
            "advertising_tracking",
            "Advertising and Audience Measurement",
            "Amazon advertising infrastructure for measuring audience and campaign events.",
            "The family name and function of the advertising infrastructure are direct indicators, while the HTTPS content itself remains unreadable.",
            "https://advertising.amazon.com/",
            device_data=True,
        ),
    ),
    (
        re.compile(r"^(?=.*(?:beacon|telemetry|event|track))(?=.*\.inmobi\.com$).+", re.I),
        _catalog_entry(
            "red",
            "advertising_tracking",
            "Ad Measurement and Tracking",
            "An event endpoint or beacon within the InMobi advertising platform.",
            "The host specializes in events or measurement within an ad family, making it a tracking point rather than just an executable file.",
            "https://www.inmobi.com/",
            device_data=True,
        ),
    ),
    # ---- Ruleset v6: balanced review families (advertising / attribution) ----
    (
        re.compile(r"(?:^|\.)doubleclick\.net$", re.I),
        _catalog_entry(
            "red", "advertising", "Google Ads and campaign measurement",
            "An ad display and measurement endpoint within the DoubleClick/Google Ads network.",
            "The doubleclick.net family is documented as an advertising and conversion measurement infrastructure, serving no functional application purpose.",
            "https://support.google.com/tagassistant/answer/2954407",
            device_data=True,
        ),
    ),
    (
        re.compile(r"(?:^|\.)amazon-adsystem\.com$", re.I),
        _catalog_entry(
            "red", "advertising", "Amazon Ads",
            "An advertising and audience measurement endpoint within the Amazon advertising platform.",
            "amazon-adsystem.com is dedicated to advertising and interest measurement, not to Amazon's functional services.",
            "https://advertising.amazon.com/",
            device_data=True,
        ),
    ),
    (
        re.compile(r"(?:^|\.)iadsdk\.apple\.com$", re.I),
        _catalog_entry(
            "red", "advertising", "Apple Ads",
            "Apple's dedicated advertising interface and campaign measurement within apps.",
            "iAds/iAd Producer is documented as a dedicated advertising platform; the host is specialized for ad measurement.",
            "https://developer.apple.com/iad/",
            device_data=True,
        ),
    ),
    (
        re.compile(r"(?:^|\.)clarity\.ms$", re.I),
        _catalog_entry(
            "red", "behavior_analytics", "User experience recording — Clarity",
            "Microsoft Clarity endpoint for session recording and user behavior analysis.",
            "Clarity documentation mentions session recording and user movements, which constitutes explicit behavioral tracking.",
            "https://learn.microsoft.com/en-us/clarity/",
            device_data=True,
        ),
    ),
    (
        re.compile(r"(?:^|\.)demdex\.net$", re.I),
        _catalog_entry(
            "red", "audience_tracking", "Audience profiles — Adobe",
            "Adobe Audience Manager endpoint for building audience profiles across websites and apps.",
            "demdex.net is known as a cross-app and cross-site audience tracking infrastructure.",
            "https://experienceleague.adobe.com/docs/audience-manager.html",
            device_data=True,
        ),
    ),
    (
        re.compile(r"(?:^|\.)adjust\.com$", re.I),
        _catalog_entry(
            "red", "attribution", "Measurement and attribution — Adjust",
            "Adjust interface for install attribution and app event tracking.",
            "Adjust documentation defines its endpoints as collecting device and advertising identifiers for install attribution.",
            "https://help.adjust.com/",
            device_data=True,
        ),
    ),
    (
        re.compile(r"(?:^|\.)appsflyer(?:sdk)?\.com$", re.I),
        _catalog_entry(
            "red", "attribution", "Measurement and attribution — AppsFlyer",
            "AppsFlyer endpoints for install attribution, event tracking, and SKAdNetwork.",
            "AppsFlyer documentation clarifies the collection of device and advertising identifiers for attribution and measurement purposes.",
            "https://support.appsflyer.com/",
            device_data=True,
        ),
    ),
    (
        re.compile(r"(?:^|\.)branch\.io$", re.I),
        _catalog_entry(
            "red", "attribution", "Attribution and deep links — Branch",
            "Branch endpoints for attribution, deep linking, and event tracking.",
            "Branch documentation mentions event tracking and user or device identifiers required for attribution.",
            "https://help.branch.io/developer-hub/docs/track-branch-events",
            device_data=True,
        ),
    ),
    (
        re.compile(r"(?:^|\.)singular\.net$", re.I),
        _catalog_entry(
            "red", "attribution", "Measurement and Attribution — Singular",
            "Singular endpoint for attribution, campaign measurement, and SKAdNetwork.",
            "Singular is an attribution and ad measurement platform; the skan host is dedicated to SKAdNetwork signals.",
            "https://support.singular.net/",
            device_data=True,
        ),
    ),
    (
        re.compile(r"(?:^|\.)criteo\.(?:com|net)$", re.I),
        _catalog_entry(
            "red", "advertising", "Advertising and Retargeting — Criteo",
            "Criteo measurement endpoint for advertising and retargeting across apps.",
            "Criteo is an advertising and retargeting platform; client-side metrics track user behavior.",
            "https://www.criteo.com/",
            device_data=True,
        ),
    ),
    (
        re.compile(r"(?:^|\.)moloco\.com$", re.I),
        _catalog_entry(
            "red", "advertising", "Performance Advertising — Moloco",
            "Moloco ad metrics endpoint for targeting and performance measurement.",
            "Moloco is a performance advertising platform; the metrics host is dedicated to campaign data, not app functionality.",
            "https://www.moloco.com/",
            device_data=True,
        ),
    ),
    (
        re.compile(r"(?:^|\.)braze\.com$", re.I),
        _catalog_entry(
            "red", "marketing_automation", "Behavioral Marketing — Braze",
            "Braze SDK endpoint for user tracking and behavioral marketing messages.",
            "Braze collects user and device events for marketing automation, which constitutes behavioral tracking.",
            "https://www.braze.com/docs/",
            device_data=True,
        ),
    ),
    (
        re.compile(r"(?:^|\.)mixpanel\.com$", re.I),
        _catalog_entry(
            "red", "behavior_analytics", "Behavioral Analytics — Mixpanel",
            "Mixpanel interface for logging user events and analytics.",
            "Mixpanel documentation defines its interfaces as collecting user events and identifiers.",
            "https://developer.mixpanel.com/",
            device_data=True,
        ),
    ),
    (
        re.compile(r"(?:^|\.)segment\.io$", re.I),
        _catalog_entry(
            "red", "behavior_analytics", "Event Collection — Segment",
            "Segment interface for collecting user events and forwarding them to analytics platforms.",
            "Segment distributes user events to external analytics and marketing tools.",
            "https://segment.com/docs/",
            device_data=True,
        ),
    ),
    (
        re.compile(r"(?:^|\.)dataroid\.com$", re.I),
        _catalog_entry(
            "red", "behavior_analytics", "Experience Analytics — Dataroid",
            "Dataroid endpoint for measuring in-app user experience.",
            "Dataroid is a digital experience analytics platform that collects usage and device events.",
            "https://www.dataroid.com/",
            device_data=True,
        ),
    ),
    (
        re.compile(r"(?:^|\.)app-measurement\.com$", re.I),
        _catalog_entry(
            "red", "behavior_analytics", "Firebase Measurement",
            "Google Analytics for Firebase endpoint for measuring app events.",
            "app-measurement.com is the documented host for Firebase Analytics event ingestion.",
            "https://firebase.google.com/docs/analytics",
            device_data=True,
        ),
    ),
    (
        re.compile(r"^app-analytics-services\.com$", re.I),
        _catalog_entry(
            "red", "behavior_analytics", "Aggregate usage analytics",
            "A usage analytics endpoint connected to by many unrelated apps.",
            "Connections from more than fifteen different apps prove it is a third-party analytics SDK.",
            "",
            device_data=True,
        ),
    ),
    (
        re.compile(r"^firebaselogging-pa\.googleapis\.com$", re.I),
        _catalog_entry(
            "red", "behavior_analytics", "Firebase Remote Logs",
            "Firebase Logging endpoint for sending app logs and events to Google.",
            "Custom logging host for uploading logs and analytics, not for core app functionality.",
            "https://firebase.google.com/",
            device_data=True,
        ),
    ),
    (
        re.compile(r"(?:^|\.)google-analytics\.com$", re.I),
        _catalog_entry(
            "red", "behavior_analytics", "Google Analytics",
            "Google Analytics measurement point for user events and sessions.",
            "Google Analytics is an audience measurement platform; the measurement host provides no operational app functionality.",
            "https://support.google.com/analytics/",
            device_data=True,
        ),
    ),
    (
        re.compile(r"^analytics(?:-ipv6)?\.tiktok\.com$|^analytics-ipv6\.tiktokw\.us$", re.I),
        _catalog_entry(
            "red", "behavior_analytics", "TikTok Analytics",
            "In-app TikTok usage analytics endpoint.",
            "Custom analytics host for collecting usage events, not for app operation.",
            "https://www.tiktok.com/",
            device_data=True,
        ),
    ),
    (
        re.compile(r"^analytics\.twitter\.com$", re.I),
        _catalog_entry(
            "red", "behavior_analytics", "X Analytics",
            "In-app X platform usage analytics endpoint.",
            "Custom analytics host for collecting usage events, not for app operation.",
            "https://x.com/",
            device_data=True,
        ),
    ),
    (
        re.compile(r"(?:^|\.)avcdn\.net$|^analytics-prod\.tf\.ff\.avast\.com$", re.I),
        _catalog_entry(
            "red", "behavior_analytics", "Security usage analytics",
            "Avast/Norton product usage analytics endpoint.",
            "Analytics host that collects usage events, separate from the security functionality itself.",
            "https://www.norton.com/",
            device_data=True,
        ),
    ),
    (
        re.compile(r"^analytics.*\.mtgglobals\.com$", re.I),
        _catalog_entry(
            "red", "behavior_analytics", "Third-party analytics",
            "Analytics endpoint within an external provider's domain.",
            "The host's specialization in analytics makes it a data collection point, not a functional service.",
            "",
            device_data=True,
        ),
    ),
    (
        re.compile(r"^telemetry\.|^(?:mobile-)?telemetry[.-]", re.I),
        _catalog_entry(
            "red", "telemetry", "Telemetry",
            "Host dedicated to sending device and usage metrics to a third party.",
            "The 'telemetry' prefix in the host is a direct indicator of operational device data collection.",
            "",
            device_data=True,
        ),
    ),
    (
        re.compile(r"^cdn\.prod\.metrics\.imdb(?:\.a2z)?\.com$", re.I),
        _catalog_entry(
            "red", "behavior_analytics", "IMDb Metrics",
            "IMDb usage metrics endpoint via CDN.",
            "Custom metrics host for usage measurement, not for IMDb content itself.",
            "",
            device_data=True,
        ),
    ),
    # ---- Ruleset v6: operational telemetry (orange, monitor) ----
    (
        re.compile(r"(?:^|\.)crashlytics\.com$|^crashlyticsreports-pa\.googleapis\.com$", re.I),
        _catalog_entry(
            "orange", "crash_diagnostics", "Crash reports — Crashlytics",
            "Firebase Crashlytics endpoint for uploading crash reports and their settings.",
            "Crash reports contain device data but have direct operational value; monitored, not blocked.",
            "https://firebase.google.com/docs/crashlytics",
            device_data=True,
        ),
    ),
    (
        re.compile(r"(?:^|\.)sentry\.io$|^sentry-report\.|^sentry-antitrack\.", re.I),
        _catalog_entry(
            "orange", "crash_diagnostics", "Crash reports — Sentry",
            "Sentry endpoint for uploading crash reports and app sessions.",
            "Crash reports contain device data but have direct operational value; monitored, not blocked.",
            "https://docs.sentry.io/",
            device_data=True,
        ),
    ),
    (
        re.compile(r"(?:^|\.)bugsnag\.com$", re.I),
        _catalog_entry(
            "orange", "crash_diagnostics", "Crash reports — Bugsnag",
            "Bugsnag endpoint for uploading app sessions and crash reports.",
            "Crash reports contain device data but have direct operational value; monitored, not blocked.",
            "https://docs.bugsnag.com/",
            device_data=True,
        ),
    ),
    (
        re.compile(r"(?:^|\.)appcenter\.ms$", re.I),
        _catalog_entry(
            "orange", "crash_diagnostics", "App Center Diagnostics",
            "Microsoft App Center endpoint for analytics and crashes during development and runtime.",
            "Operational diagnostic data; monitored, not blocked to maintain app stability.",
            "https://learn.microsoft.com/en-us/appcenter/",
            device_data=True,
        ),
    ),
    (
        re.compile(r"^firebaseinstallations\.googleapis\.com$", re.I),
        _catalog_entry(
            "orange", "service_identity", "Firebase Identity",
            "Registers the app version with Firebase and links it to an installation ID.",
            "The installation ID is device data, but breaking it may disrupt FCM notifications; monitored, not blocked.",
            "https://firebase.google.com/docs/projects/manage-installations",
            device_data=True,
        ),
    ),
    (
        re.compile(r"^device-provisioning\.googleapis\.com$", re.I),
        _catalog_entry(
            "orange", "service_identity", "Device Provisioning — Google",
            "Operational device provisioning linked to Google services and notifications.",
            "Operational provisioning endpoint; breaking it may disrupt notifications, so it is monitored, not blocked.",
            "https://developers.google.com/",
            device_data=True,
        ),
    ),
    (
        re.compile(r"^firebaseremoteconfig\.googleapis\.com$", re.I),
        _catalog_entry(
            "orange", "remote_config", "Remote Settings — Firebase",
            "Fetches app settings remotely from Firebase Remote Config.",
            "Changes app behavior remotely but is part of its operation; monitored, not blocked.",
            "https://firebase.google.com/docs/remote-config",
            device_data=True,
        ),
    ),
    (
        re.compile(r"^metrics\.icloud\.com$", re.I),
        _catalog_entry(
            "orange", "system_metrics", "Apple System Metrics",
            "Operational metrics endpoint for Apple services and iCloud.",
            "Operational system metrics from the device provider itself; monitored, not blocked.",
            "https://www.apple.com/privacy/",
            device_data=True,
        ),
    ),
)


class SafeHTTPSStudy:
    """Fetch bounded public HTTPS metadata without cookies, redirects, or private IPs."""

    def __init__(self, timeout: float = 3.5, maximum_bytes: int = 65536):
        self.timeout = max(0.5, float(timeout))
        self.maximum_bytes = min(max(int(maximum_bytes), 4096), 131072)

    @staticmethod
    def _targets(domain: str) -> list[tuple[int, tuple[Any, ...], str]]:
        targets: list[tuple[int, tuple[Any, ...], str]] = []
        seen: set[str] = set()
        for family, socktype, proto, _, sockaddr in socket.getaddrinfo(
            domain, 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
        ):
            if socktype != socket.SOCK_STREAM:
                continue
            address = str(sockaddr[0])
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError:
                continue
            if not parsed.is_global or address in seen:
                continue
            seen.add(address)
            targets.append((family, sockaddr, address))
        return targets[:4]

    @staticmethod
    def _certificate_name(values: Any) -> str:
        parts = []
        for group in values or []:
            for key, value in group:
                if key in {"organizationName", "commonName"}:
                    parts.append(_bounded(value, 120))
        return " / ".join(dict.fromkeys(part for part in parts if part))[:240]

    @staticmethod
    def _html_meta(body: str) -> tuple[str, str]:
        title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        description_match = re.search(
            r"<meta[^>]+(?:name|property)=[\"'](?:description|og:description)[\"'][^>]+content=[\"'](.*?)[\"']",
            body,
            re.I | re.S,
        ) or re.search(
            r"<meta[^>]+content=[\"'](.*?)[\"'][^>]+(?:name|property)=[\"'](?:description|og:description)[\"']",
            body,
            re.I | re.S,
        )
        title = _bounded(html.unescape(re.sub(r"<[^>]+>", " ", title_match.group(1))), 200) if title_match else ""
        description = _bounded(html.unescape(re.sub(r"<[^>]+>", " ", description_match.group(1))), 320) if description_match else ""
        return title, description

    def study(self, domain: str) -> dict[str, Any]:
        clean = _normalize_domain(domain)
        if not clean:
            return {"ok": False, "error": "Invalid domain name"}
        try:
            targets = self._targets(clean)
        except OSError as exc:
            return {"ok": False, "error": _bounded(exc, 180)}
        if not targets:
            return {"ok": False, "error": "No safe public internet address available for study"}

        last_error = "Failed to establish a public HTTPS connection"
        context = ssl.create_default_context()
        request = (
            f"GET / HTTP/1.1\r\nHost: {clean}\r\n"
            "User-Agent: PrivacyProtector-DomainStudy/3.0\r\n"
            "Accept: text/html,application/json;q=0.7,*/*;q=0.2\r\n"
            "Accept-Encoding: identity\r\nRange: bytes=0-32767\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        for family, sockaddr, address in targets:
            raw: socket.socket | None = None
            tls: ssl.SSLSocket | None = None
            try:
                raw = socket.socket(family, socket.SOCK_STREAM)
                raw.settimeout(self.timeout)
                raw.connect(sockaddr)
                tls = context.wrap_socket(raw, server_hostname=clean)
                tls.settimeout(self.timeout)
                certificate = tls.getpeercert()
                tls.sendall(request)
                chunks = bytearray()
                while len(chunks) < self.maximum_bytes:
                    part = tls.recv(min(8192, self.maximum_bytes - len(chunks)))
                    if not part:
                        break
                    chunks.extend(part)
                raw_response = bytes(chunks)
                head, _, body_bytes = raw_response.partition(b"\r\n\r\n")
                head_text = head.decode("iso-8859-1", errors="replace")
                lines = head_text.split("\r\n")
                status_match = re.match(r"HTTP/\S+\s+(\d{3})", lines[0] if lines else "")
                headers: dict[str, str] = {}
                for line in lines[1:]:
                    if ":" not in line:
                        continue
                    key, value = line.split(":", 1)
                    key = key.strip().lower()
                    if key in {"content-type", "server", "location", "via", "x-powered-by"}:
                        headers[key] = _bounded(value, 240)
                body = body_bytes.decode("utf-8", errors="replace")
                title, description = self._html_meta(body)
                redirect_host = ""
                if headers.get("location"):
                    redirect_host = _normalize_domain(urlsplit(headers["location"]).hostname or "")
                return {
                    "ok": True,
                    "studiedAt": _now_iso(),
                    "addressHash": hashlib.sha256(address.encode("ascii")).hexdigest()[:12],
                    "httpStatus": int(status_match.group(1)) if status_match else 0,
                    "contentType": headers.get("content-type", ""),
                    "server": headers.get("server", ""),
                    "poweredBy": headers.get("x-powered-by", ""),
                    "via": headers.get("via", ""),
                    "redirectHost": redirect_host,
                    "title": title,
                    "description": description,
                    "certificateSubject": self._certificate_name(certificate.get("subject")),
                    "certificateIssuer": self._certificate_name(certificate.get("issuer")),
                    "bytesRead": len(raw_response),
                    "privacy": "No cookies, device data, or account paths were sent; only the public HTTPS root was studied.",
                }
            except (OSError, ssl.SSLError, ValueError) as exc:
                last_error = _bounded(exc, 180)
            finally:
                if tls:
                    try:
                        tls.close()
                    except OSError:
                        pass
                elif raw:
                    try:
                        raw.close()
                    except OSError:
                        pass
        return {"ok": False, "studiedAt": _now_iso(), "error": last_error}
def _catalog_for_domain(domain: str) -> dict[str, Any] | None:
    # The reviewed rules layer takes precedence over the old catalog.
    reviewed = verdict_for(domain)
    if reviewed:
        return reviewed
    catalog = CURATED_DOMAIN_CATALOG.get(domain)
    if catalog:
        return catalog
    for pattern, family_catalog in CURATED_DOMAIN_FAMILIES:
        if pattern.search(domain):
            return family_catalog
    if domain == "_dns.resolver.arpa" or (
        domain.startswith("lb._dns-sd._udp.") and domain.endswith(".in-addr.arpa")
    ):
        return _catalog_entry(
            "green",
            "dns_service_discovery",
            "Local DNS service discovery",
            "Operational DNS log for resolver or local network service discovery.",
            "Name structure and query type are specific to DNS discovery; not an application data collection point.",
        )
    return None


class DomainClassificationEngine:
    def __init__(
        self,
        path: Path,
        *,
        active_analysis: bool = True,
        classification_paused: bool = False,
        probe: SafeHTTPSStudy | None = None,
        app_purpose_profiles: dict[str, dict[str, Any]] | None = None,
    ):
        self.path = path
        self.active_analysis = bool(active_analysis)
        self.classification_paused = bool(classification_paused)
        self.probe = probe or SafeHTTPSStudy()
        self.app_purpose_profiles = {
            str(bundle).lower(): dict(settings)
            for bundle, settings in (app_purpose_profiles or {}).items()
        }
        self.lock = threading.RLock()
        self.data: dict[str, Any] = {
            "version": ENGINE_VERSION,
            "engine": "DNS Engine V3",
            "domains": {},
        }
        self.jobs: queue.Queue[str | None] = queue.Queue()
        self.pending: set[str] = set()
        self.workers: list[threading.Thread] = []
        self.stopping = threading.Event()
        self.persist_flush_seconds = PERSIST_FLUSH_SECONDS
        self._dirty = False
        self._flush_wake = threading.Event()
        self._flusher: threading.Thread | None = None
        self._load()

    @staticmethod
    def _refresh_catalog_entry(domain: str, entry: dict[str, Any]) -> bool:
        catalog = _catalog_for_domain(domain)
        if not catalog:
            return False
        fresh = DomainClassificationEngine._base_entry(domain)
        previous_risk = str(entry.get("risk") or "")
        local_evidence = any(
            str(item).startswith("Local session:") for item in entry.get("evidence", [])
        )
        # Confirmed local evidence takes precedence over the reviewed catalog even when they agree on
        # Red: The update must not replace confirmed_privacy_violation with a generic category.
        preserve_local_red = local_evidence and previous_risk == "red"
        changed = False
        for key in (
            "risk", "riskLabel", "category", "categoryLabel", "stage", "stageLabel",
            "confidence", "confidenceLabel", "summary", "reason", "privacyRelevant",
            "deviceDataAccess", "developerModeCheck", "analyzedAt",
        ):
            if preserve_local_red and key in {
                "risk", "riskLabel", "category", "categoryLabel", "stage", "stageLabel",
                "confidence", "confidenceLabel", "summary", "reason", "privacyRelevant",
                "deviceDataAccess", "developerModeCheck", "analyzedAt",
            }:
                continue
            if entry.get(key) != fresh.get(key):
                entry[key] = fresh.get(key)
                changed = True
        evidence = list(entry.get("evidence", []))
        if "Matched reviewed V3 catalog" not in evidence:
            evidence.append("Matched reviewed V3 catalog")
            entry["evidence"] = evidence[-30:]
            changed = True
        sources = list(entry.get("researchSources", []))
        for source in fresh.get("researchSources", []):
            if source not in sources:
                sources.append(source)
                changed = True
        entry["researchSources"] = sources[-12:]
        if preserve_local_red:
            history = entry.get("classificationHistory", [])
            if isinstance(history, list):
                cleaned_history = [
                    item
                    for item in history
                    if not (
                        isinstance(item, dict)
                        and item.get("ruleset") == CLASSIFICATION_RULESET_VERSION
                        and item.get("from") == "red"
                        and item.get("to") != "red"
                    )
                ]
                if cleaned_history != history:
                    entry["classificationHistory"] = cleaned_history
                    entry["reclassifiedAt"] = (
                        str(cleaned_history[-1].get("at", "")) if cleaned_history else ""
                    )
                    changed = True
        elif (
            previous_risk in RISK_ORDER
            and RISK_ORDER[fresh["risk"]] > RISK_ORDER[previous_risk]
        ):
            history = entry.get("classificationHistory", [])
            if not isinstance(history, list):
                history = []
            history.append(
                {
                    "from": previous_risk,
                    "to": fresh["risk"],
                    "at": _now_iso(),
                    "ruleset": CLASSIFICATION_RULESET_VERSION,
                    "reason": "Re-evaluation after documented provider rule update",
                }
            )
            entry["classificationHistory"] = history[-20:]
            entry["reclassifiedAt"] = history[-1]["at"]
            changed = True
        return changed

    @staticmethod
    def _annotate_context_locked(
        domain: str,
        entry: dict[str, Any],
        category: str,
        contexts: list[str],
    ) -> bool:
        """Log the blocking trace and location justification without changing the color."""
        changed = False
        block_safe = is_block_safe(domain, category)
        if entry.get("blockSafe") != block_safe:
            entry["blockSafe"] = block_safe
            changed = True
        note = (
            "Blocking it does not impair application functionality."
            if block_safe
            else "Operational path or shared structure; monitored but not blocked even if red."
        )
        if entry.get("blockSafeNote") != note:
            entry["blockSafeNote"] = note
            changed = True
        findings = location_findings(category, contexts)
        if findings != (entry.get("locationPurpose") or {}):
            if findings:
                entry["locationPurpose"] = findings
            else:
                entry.pop("locationPurpose", None)
            changed = True
        return changed

    @staticmethod
    def _apply_sensitive_context_locked(domain: str, entry: dict[str, Any]) -> bool:
        """Escalate the judgment to red if it involves behavioral collection within a banking or government app."""
        contexts = list(entry.get("appContexts", []) or []) + list(
            entry.get("appBundles", []) or []
        )
        category = str(entry.get("category") or "")
        changed = DomainClassificationEngine._annotate_context_locked(
            domain, entry, category, contexts
        )
        escalation = escalate_for_context(
            domain, str(entry.get("risk") or ""), category, contexts
        )
        if not escalation:
            return changed
        previous = str(entry.get("risk") or "")
        entry.update(
            {
                "risk": "red",
                "riskLabel": RISK_LABELS["red"],
                "categoryLabel": escalation["categoryLabel"],
                "summary": escalation["summary"],
                "reason": escalation["reason"],
                "privacyRelevant": True,
                "deviceDataAccess": True,
                "stage": "studied",
                "stageLabel": STAGE_LABELS["studied"],
                "confidence": 90,
                "confidenceLabel": "High confidence",
            }
        )
        evidence = list(entry.get("evidence", []))
        marker = "Escalation: Behavioral collection in sensitive app despite tracking feature being disabled"
        if marker not in evidence:
            evidence.append(marker)
            entry["evidence"] = evidence[-30:]
        history = entry.get("classificationHistory")
        if not isinstance(history, list):
            history = []
        history.append(
            {
                "from": previous,
                "to": "red",
                "at": _now_iso(),
                "ruleset": CLASSIFICATION_RULESET_VERSION,
                "reason": "Persistent tracking within a banking or government app despite user refusal",
            }
        )
        entry["classificationHistory"] = history[-20:]
        entry["reclassifiedAt"] = history[-1]["at"]
        return True

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                self.data["domains"] = loaded.get("domains", {}) if isinstance(loaded.get("domains"), dict) else {}
                changed = "functions" in loaded
                for domain, entry in self.data["domains"].items():
                    if isinstance(entry, dict):
                        if "lastObservedAt" not in entry:
                            entry["lastObservedAt"] = ""
                            changed = True
                        if (
                            not self.classification_paused
                            and entry.get("stage") != "new"
                            and entry.get("risk") != "unclassified"
                        ):
                            changed = self._refresh_catalog_entry(domain, entry) or changed
                            changed = self._apply_sensitive_context_locked(
                                domain, entry
                            ) or changed
                            for bundle in list(entry.get("appBundles", []) or []):
                                changed = self._apply_app_purpose_locked(
                                    domain, entry, str(bundle)
                                ) or changed
                if changed:
                    self._save_locked()
        except (OSError, ValueError, json.JSONDecodeError):
            corrupt = self.path.with_suffix(".corrupt.json")
            try:
                os.replace(self.path, corrupt)
            except OSError:
                pass

    def _mark_dirty_locked(self) -> None:
        """Record that the file is stale and let the flusher write it.

        Called from paths that run while a DNS answer is waiting; the write
        itself costs far more than the whole upstream lookup.
        """
        self._dirty = True
        if self.persist_flush_seconds <= 0:
            self._save_locked()
            self._dirty = False
            return
        if self.stopping.is_set():
            return
        if self._flusher is None or not self._flusher.is_alive():
            self._flusher = threading.Thread(
                target=self._flusher_loop, name="domain-classification-flush", daemon=True
            )
            self._flusher.start()

    def _flusher_loop(self) -> None:
        while not self.stopping.is_set():
            self._flush_wake.wait(self.persist_flush_seconds)
            self._flush_wake.clear()
            self.flush()

    def flush(self) -> bool:
        """Persist pending observations. Returns True when a write happened."""
        with self.lock:
            if not self._dirty:
                return False
            self._dirty = False
            try:
                self._save_locked()
            except OSError:
                # Keep the pending state so the next flush retries the write.
                self._dirty = True
                return False
        return True

    def _save_locked(self) -> None:
        self._dirty = False
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix(".tmp")
        payload = {
            "version": ENGINE_VERSION,
            "engine": "DNS Engine V3",
            "classificationRuleset": CLASSIFICATION_RULESET_VERSION,
            "updatedAt": _now_iso(),
            "definitions": {
                "unclassified": RISK_LABELS["unclassified"],
                "green": RISK_LABELS["green"],
                "orange": RISK_LABELS["orange"],
                "red": RISK_LABELS["red"],
                "new": "Newly observed domain, not yet classified or studied.",
                "preliminary": "Initial automated classification appearing immediately upon observation, subject to change after evidence collection.",
                "studied": "Reviewed clues or general DNS/HTTPS data collected; confidence level remains visible.",
            },
            "domains": self.data["domains"],
        }
        temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.replace(temp, self.path)

    @staticmethod
    def _new_entry(domain: str) -> dict[str, Any]:
        stamp = _now_iso()
        return {
            "domain": domain,
            "risk": "unclassified",
            "riskLabel": RISK_LABELS["unclassified"],
            "category": "unclassified",
            "categoryLabel": "Pending new classification plan",
            "stage": "new",
            "stageLabel": STAGE_LABELS["new"],
            "confidence": 0,
            "confidenceLabel": "Not yet classified",
            "summary": "Domain and observation data saved without issuing a classification judgment.",
            "reason": "Classification deferred until the new classification plan is adopted.",
            "privacyRelevant": False,
            "deviceDataAccess": False,
            "developerModeCheck": False,
            "firstSeen": stamp,
            "lastSeen": stamp,
            "lastObservedAt": "",
            "analyzedAt": "",
            "lastProbeAt": "",
            "hits": 0,
            "qtypes": [],
            "transports": [],
            "decisions": [],
            "cnameChain": [],
            "appContexts": [],
            "appBundles": [],
            "evidence": ["Observation saved pending new classification plan"],
            "researchSources": [],
            "networkStudy": {},
            "aiVerdict": {},
            "aiReviewedAt": "",
            "classificationHistory": [],
            "reclassifiedAt": "",
        }

    def defer_all_classifications(self) -> dict[str, int]:
        """Reset classification results while preserving every observed domain."""
        preserved_keys = (
            "firstSeen",
            "lastSeen",
            "lastObservedAt",
            "hits",
            "qtypes",
            "transports",
            "decisions",
            "cnameChain",
            "appContexts",
            "appBundles",
            "aiVerdict",
            "aiReviewedAt",
        )
        with self.lock:
            before = len(self.data["domains"])
            deferred: dict[str, dict[str, Any]] = {}
            for domain, previous in self.data["domains"].items():
                entry = self._new_entry(domain)
                if isinstance(previous, dict):
                    for key in preserved_keys:
                        if key in previous:
                            entry[key] = json.loads(
                                json.dumps(previous[key], ensure_ascii=False)
                            )
                deferred[domain] = entry
            self.data["domains"] = deferred
            self._save_locked()
            return {"before": before, "after": len(deferred), "deferred": len(deferred)}

    def reclassify_all(self) -> dict[str, int]:
        """Re-run the current ruleset over every preserved domain.

        Observation data (hits, qtypes, app bundles...) is preserved; only the
        verdict fields are rebuilt. Local red evidence is never downgraded.
        """
        with self.lock:
            counts = {"studied": 0, "preliminary": 0, "preservedLocalRed": 0}
            for clean, entry in self.data["domains"].items():
                if not isinstance(entry, dict):
                    continue
                previous = str(entry.get("risk") or "unclassified")
                local_evidence = any(
                    str(item).startswith("Local session:")
                    for item in entry.get("evidence", [])
                )
                base = self._base_entry(clean)
                if (
                    local_evidence
                    and previous == "red"
                    and RISK_ORDER[base["risk"]] < RISK_ORDER["red"]
                ):
                    counts["preservedLocalRed"] += 1
                    continue
                for key in (
                    "risk", "riskLabel", "category", "categoryLabel", "stage",
                    "stageLabel", "confidence", "confidenceLabel", "summary",
                    "reason", "privacyRelevant", "deviceDataAccess",
                    "developerModeCheck", "analyzedAt",
                ):
                    entry[key] = base[key]
                study = entry.get("networkStudy", {})
                if isinstance(study, dict) and study:
                    self._apply_network_study_locked(clean, entry, study)
                for bundle in list(entry.get("appBundles", []) or []):
                    self._apply_app_purpose_locked(clean, entry, str(bundle))
                self._apply_shared_sdk_evidence_locked(clean, entry, base)
                # Saved AI review is reapplied on top of the built rule,
                # otherwise the "Reclassify" button clears all reviewed items.
                stored_verdict = entry.get("aiVerdict")
                if isinstance(stored_verdict, dict) and stored_verdict.get("color"):
                    self.apply_ai_verdict(clean, stored_verdict, record_history=False)
                counts["studied" if entry.get("stage") == "studied" else "preliminary"] += 1
                if previous != entry.get("risk"):
                    history = entry.get("classificationHistory", [])
                    if not isinstance(history, list):
                        history = []
                    history.append(
                        {
                            "from": previous,
                            "to": entry["risk"],
                            "at": _now_iso(),
                            "ruleset": CLASSIFICATION_RULESET_VERSION,
                            "reason": "Comprehensive reclassification after engine rule update",
                        }
                    )
                    entry["classificationHistory"] = history[-20:]
                    entry["reclassifiedAt"] = history[-1]["at"]
            self._save_locked()
            return counts

    @staticmethod
    def _base_entry(domain: str, hint_text: str = "") -> dict[str, Any]:
        stamp = _now_iso()
        catalog = _catalog_for_domain(domain)
        if catalog:
            risk = catalog["risk"]
            source = catalog.get("source", "")
            return {
                "domain": domain,
                "risk": risk,
                "riskLabel": RISK_LABELS[risk],
                "category": catalog["category"],
                "categoryLabel": catalog["categoryLabel"],
                "stage": "studied",
                "stageLabel": STAGE_LABELS["studied"],
                "confidence": 92,
                "confidenceLabel": "High confidence",
                "summary": catalog["summary"],
                "reason": catalog["reason"],
                "privacyRelevant": risk == "red",
                "deviceDataAccess": bool(catalog.get("deviceDataAccess")),
                "developerModeCheck": bool(catalog.get("developerModeCheck")),
                "firstSeen": stamp,
                "lastSeen": stamp,
                "lastObservedAt": "",
                "analyzedAt": stamp,
                "lastProbeAt": "",
                "hits": 0,
                "qtypes": [],
                "transports": [],
                "decisions": [],
                "cnameChain": [],
                "appContexts": [],
                "evidence": ["Matched reviewed V3 catalog"],
                "researchSources": [source] if source else [],
                "networkStudy": {},
            }

        text = f"{domain} {hint_text}".lower()
        if RED_PATTERN.search(text):
            risk, category, label, confidence = "red", "privacy_signal", "Tracking or privacy signal", 64
            summary = "Strong indication of tracking or privacy data found in name or description."
        elif ORANGE_PATTERN.search(text):
            risk, category, label, confidence = "orange", "device_telemetry", "Operational device data", 56
            summary = "The service appears related to diagnostics, notifications, or device operational information."
        elif GREEN_PATTERN.search(text):
            risk, category, label, confidence = "green", "functional_service", "Operational service", 52
            summary = "Name initially suggests authentication, API, files, or protection service."
        else:
            risk, category, label, confidence = "green", "general_network", "General network service", 35
            summary = "No direct privacy indication in domain name; classification is preliminary pending full study."
        return {
            "domain": domain,
            "risk": risk,
            "riskLabel": RISK_LABELS[risk],
            "category": category,
            "categoryLabel": label,
            "stage": "preliminary",
            "stageLabel": STAGE_LABELS["preliminary"],
            "confidence": confidence,
            "confidenceLabel": "Medium confidence" if confidence >= 50 else "Preliminary confidence",
            "summary": summary,
            "reason": "Initial classification from domain name and local description; will be updated after public evidence analysis.",
            "privacyRelevant": risk == "red",
            "deviceDataAccess": risk in {"orange", "red"},
            "developerModeCheck": bool(re.search(r"developer.?mode|jailbreak|root.?check|integrity", text)),
            "firstSeen": stamp,
            "lastSeen": stamp,
            "lastObservedAt": "",
            "analyzedAt": "",
            "lastProbeAt": "",
            "hits": 0,
            "qtypes": [],
            "transports": [],
            "decisions": [],
            "cnameChain": [],
            "appContexts": [],
            "evidence": ["Preliminary classification from domain name"],
            "researchSources": [],
            "networkStudy": {},
        }

    @staticmethod
    def _append_unique(entry: dict[str, Any], key: str, values: list[str], maximum: int) -> bool:
        current = list(entry.get(key, []))
        changed = False
        for value in values:
            clean = _bounded(value, 240)
            if clean and clean not in current:
                current.append(clean)
                changed = True
        if len(current) > maximum:
            current = current[-maximum:]
            changed = True
        entry[key] = current
        return changed

    def _apply_network_study_locked(
        self,
        domain: str,
        entry: dict[str, Any],
        study: dict[str, Any],
    ) -> dict[str, Any]:
        catalog = _catalog_for_domain(domain)
        text = " ".join(
            str(study.get(key, ""))
            for key in ("title", "description", "certificateSubject", "server", "redirectHost")
        )
        inferred = self._base_entry(domain, text)
        if catalog or RISK_ORDER[inferred["risk"]] > RISK_ORDER.get(entry.get("risk"), -1):
            for key in (
                "risk", "riskLabel", "category", "categoryLabel", "summary", "privacyRelevant",
                "deviceDataAccess", "developerModeCheck",
            ):
                entry[key] = inferred[key]
            self._append_unique(entry, "evidence", ["Additional signal from public HTTPS data"], 30)
        if study.get("ok"):
            entry["stage"] = "studied"
            entry["stageLabel"] = STAGE_LABELS["studied"]
            entry["analyzedAt"] = str(study.get("studiedAt") or _now_iso())
            if catalog:
                entry["confidence"] = max(92, int(entry.get("confidence", 0)))
                entry["confidenceLabel"] = "High confidence"
            else:
                entry["confidence"] = max(58, int(entry.get("confidence", 0)))
                entry["confidenceLabel"] = "Medium confidence"
                entry["reason"] = (
                    "TLS certificate and limited public response collected along with domain name and DNS evidence. "
                    "Account paths or encrypted contents were not inspected."
                )
            self._append_unique(entry, "evidence", ["Safe scan of public HTTPS root"], 30)
            redirect = study.get("redirectHost")
            if redirect:
                self._append_unique(entry, "cnameChain", [str(redirect)], 30)
        else:
            self._append_unique(
                entry,
                "evidence",
                [f"HTTPS scan failed: {_bounded(study.get('error'), 120)}"],
                30,
            )
        return inferred

    @staticmethod
    def _matches_domain_suffix(domain: str, suffix: str) -> bool:
        clean_suffix = _normalize_domain(suffix)
        return bool(
            clean_suffix
            and (domain == clean_suffix or domain.endswith(f".{clean_suffix}"))
        )

    def _apply_app_purpose_locked(
        self,
        domain: str,
        entry: dict[str, Any],
        app_bundle: str,
    ) -> bool:
        bundle = str(app_bundle or "").strip().lower()
        purpose = self.app_purpose_profiles.get(bundle)
        if not bundle or not purpose:
            return False
        expected = any(
            self._matches_domain_suffix(domain, suffix)
            for suffix in purpose.get("expectedDomainSuffixes", [])
        )
        contexts = entry.get("appPurposeContexts", {})
        if not isinstance(contexts, dict):
            contexts = {}
        context = {
            "bundleID": bundle,
            "kind": _bounded(purpose.get("purposeKind"), 80),
            "risk": _bounded(purpose.get("purposeRisk"), 16),
            "label": _bounded(purpose.get("purposeLabel"), 120),
            "reason": _bounded(purpose.get("purposeReason"), 400),
            "expectedForDomain": expected,
        }
        changed = contexts.get(bundle) != context
        contexts[bundle] = context
        entry["appPurposeContexts"] = contexts
        changed |= self._append_unique(entry, "appBundles", [bundle], 30)

        local_evidence = any(
            str(item).startswith("Local session:") for item in entry.get("evidence", [])
        )
        target_risk = str(purpose.get("purposeRisk") or "")
        current_risk = str(entry.get("risk") or "")
        if target_risk == "green":
            can_cap_health_access = (
                expected
                and RISK_ORDER.get(current_risk, -1) > RISK_ORDER["green"]
                and not local_evidence
                and _catalog_for_domain(domain) is None
            )
        else:
            can_cap_health_access = (
                target_risk == "orange"
                and expected
                and current_risk == "red"
                and entry.get("category") in {"privacy_signal", "expected_health_data"}
                and not local_evidence
                and _catalog_for_domain(domain) is None
            )
        if not can_cap_health_access:
            return changed

        previous_risk = current_risk or "red"
        entry.update(
            {
                "risk": target_risk,
                "riskLabel": RISK_LABELS[target_risk],
                "category": "expected_health_data",
                "categoryLabel": "Expected health access",
                "stage": "studied",
                "stageLabel": STAGE_LABELS["studied"],
                "confidence": max(94, int(entry.get("confidence", 0))),
                "confidenceLabel": "High confidence in app context",
                "summary": "The host handles health data that the user expects from the selected app's functionality.",
                "reason": str(purpose.get("purposeReason") or "")[:400],
                "privacyRelevant": False,
                "deviceDataAccess": True,
                "analyzedAt": _now_iso(),
            }
        )
        self._append_unique(
            entry,
            "evidence",
            [f"Optional health app context: {purpose.get('purposeLabel', '')}"],
            30,
        )
        history = entry.get("classificationHistory", [])
        if not isinstance(history, list):
            history = []
        if not history or not (
            history[-1].get("from") == previous_risk
            and history[-1].get("to") == target_risk
            and history[-1].get("ruleset") == CLASSIFICATION_RULESET_VERSION
        ):
            history.append(
                {
                    "from": previous_risk,
                    "to": target_risk,
                    "at": _now_iso(),
                    "ruleset": CLASSIFICATION_RULESET_VERSION,
                    "reason": "Contextual correction for optional health app and expected host functionality",
                }
            )
        entry["classificationHistory"] = history[-20:]
        entry["reclassifiedAt"] = history[-1]["at"]
        return True

    def _apply_shared_sdk_evidence_locked(
        self, domain: str, entry: dict[str, Any], inferred: dict[str, Any]
    ) -> bool:
        """Cross-app evidence: a telemetry-patterned domain contacted by many
        unrelated apps is a third-party SDK, so its verdict becomes studied."""
        if _catalog_for_domain(domain):
            return False
        bundles = {
            str(bundle).strip().lower()
            for bundle in entry.get("appBundles", [])
            if str(bundle).strip()
        }
        if len(bundles) < SHARED_SDK_MIN_APPS:
            return False
        target = str(inferred.get("risk") or "")
        if RISK_ORDER.get(target, -1) < RISK_ORDER["orange"]:
            return False
        previous = str(entry.get("risk") or "unclassified")
        if any(
            str(item).startswith("Sharing evidence:") for item in entry.get("evidence", [])
        ):
            return False
        if RISK_ORDER.get(previous, -1) > RISK_ORDER[target]:
            target = previous  # never downgrade within this rule
        entry.update(
            {
                "risk": target,
                "riskLabel": RISK_LABELS[target],
                "stage": "studied",
                "stageLabel": STAGE_LABELS["studied"],
                "confidence": max(88, int(entry.get("confidence") or 0)),
                "confidenceLabel": "High confidence — sharing evidence",
                "reason": (
                    f"{inferred.get('categoryLabel', 'Measurement')} pattern with connection "
                    f"to {len(bundles)} different apps; widespread sharing confirms a third-party SDK."
                ),
                "privacyRelevant": True,
                "deviceDataAccess": True,
                "analyzedAt": _now_iso(),
            }
        )
        self._append_unique(
            entry,
            "evidence",
            [f"Sharing evidence: {len(bundles)} apps connect to this domain"],
            30,
        )
        if previous != target:
            history = entry.get("classificationHistory", [])
            if not isinstance(history, list):
                history = []
            history.append(
                {
                    "from": previous,
                    "to": target,
                    "at": _now_iso(),
                    "ruleset": CLASSIFICATION_RULESET_VERSION,
                    "reason": "Domain sharing evidence across multiple apps (third-party SDK)",
                }
            )
            entry["classificationHistory"] = history[-20:]
            entry["reclassifiedAt"] = history[-1]["at"]
        return True

    def observe(
        self,
        domain: str,
        *,
        qtype: str = "",
        transport: str = "",
        decision: str = "",
        cname_chain: list[str] | None = None,
        app_context: str = "",
        app_bundle: str = "",
        label: str = "",
        note: str = "",
        observed_at: str = "",
        schedule: bool = False,
        persist: bool = True,
    ) -> dict[str, Any] | None:
        clean = _normalize_domain(domain)
        if not clean:
            return None
        hint = f"{label} {note}"
        with self.lock:
            entry = self.data["domains"].get(clean)
            created = entry is None
            if created:
                entry = (
                    self._new_entry(clean)
                    if self.classification_paused
                    else self._base_entry(clean, hint)
                )
                self.data["domains"][clean] = entry
            else:
                changed = False
                if (
                    not self.classification_paused
                    and entry.get("stage") != "new"
                    and entry.get("risk") != "unclassified"
                ):
                    changed = self._refresh_catalog_entry(clean, entry) or changed
            entry["lastSeen"] = _now_iso()
            latest_observation = _latest_observation(
                entry.get("lastObservedAt", ""), observed_at
            )
            if latest_observation != entry.get("lastObservedAt", ""):
                entry["lastObservedAt"] = latest_observation
                changed = True
            entry["hits"] = int(entry.get("hits", 0)) + (1 if qtype or transport or decision else 0)
            changed = created or changed
            changed |= self._append_unique(entry, "qtypes", [qtype], 24)
            changed |= self._append_unique(entry, "transports", [transport], 8)
            changed |= self._append_unique(entry, "decisions", [decision], 8)
            changed |= self._append_unique(entry, "cnameChain", list(cname_chain or []), 30)
            changed |= self._append_unique(entry, "appContexts", [app_context], 20)
            changed |= self._append_unique(entry, "appBundles", [app_bundle], 30)
            if not self.classification_paused and hint and entry.get("stage") == "preliminary":
                preliminary = self._base_entry(clean, hint)
                if RISK_ORDER[preliminary["risk"]] > RISK_ORDER[entry["risk"]]:
                    for key in (
                        "risk", "riskLabel", "category", "categoryLabel", "summary", "reason",
                        "privacyRelevant", "deviceDataAccess", "developerModeCheck", "confidence", "confidenceLabel",
                    ):
                        entry[key] = preliminary[key]
                    changed = True
            if not self.classification_paused and entry.get("stage") != "new":
                changed = self._apply_app_purpose_locked(clean, entry, app_bundle) or changed
                changed = self._apply_sensitive_context_locked(clean, entry) or changed
            if persist and (changed or int(entry.get("hits", 0)) % 25 == 0):
                self._mark_dirty_locked()
            snapshot = json.loads(json.dumps(entry, ensure_ascii=False))
        if schedule and self.active_analysis and snapshot.get("stage") == "preliminary":
            self.schedule(clean)
        return snapshot

    def set_reviewed_category(self, domain: str, category: str) -> bool:
        """Pure collection category confirmed by reviewing the user's session, replacing the local engine's guess based on the host name
        (it used to count api3.4dvertible.com and cdn.doubleverify.com as a "functional service" and so refused to block them)."""
        from domain_verdicts import _PURE_COLLECTION_CATEGORIES

        clean = _normalize_domain(domain)
        if not clean or category not in _PURE_COLLECTION_CATEGORIES:
            return False
        with self.lock:
            entry = self.data["domains"].get(clean)
            if not entry:
                return False
            entry["category"] = category
            self._save_locked()
        return True

    def mark_privacy_evidence(
        self,
        domains: list[str],
        *,
        violations: list[str] | None = None,
        developer_check: bool = False,
        app_context: str = "",
        persist: bool = True,
    ) -> None:
        clean_domains = [_normalize_domain(value) for value in domains]
        with self.lock:
            changed = False
            for clean in clean_domains:
                if not clean:
                    continue
                entry = self.data["domains"].get(clean) or self._new_entry(clean)
                self.data["domains"][clean] = entry
                if self.classification_paused:
                    self._append_unique(
                        entry,
                        "evidence",
                        [
                            "Preserved local evidence: developer pattern check"
                            if developer_check
                            else f"Preserved local evidence: {', '.join(violations or [])}"
                        ],
                        30,
                    )
                    self._append_unique(entry, "appContexts", [app_context], 20)
                    changed = True
                    continue
                entry.update(
                    {
                        "risk": "red",
                        "riskLabel": RISK_LABELS["red"],
                        "category": "developer_mode_check" if developer_check else "confirmed_privacy_violation",
                        "categoryLabel": "Developer pattern check" if developer_check else "Locally confirmed privacy violation",
                        "stage": "studied",
                        "stageLabel": STAGE_LABELS["studied"],
                        "confidence": 99,
                        "confidenceLabel": "Locally confirmed confidence",
                        "privacyRelevant": True,
                        "deviceDataAccess": True,
                        "developerModeCheck": bool(developer_check or entry.get("developerModeCheck")),
                        "analyzedAt": _now_iso(),
                        "summary": "The domain was linked to local evidence via developer pattern check."
                        if developer_check
                        else "The domain was linked to a violation of saved privacy preferences.",
                        "reason": "Evidence comes from a local verification session, not just the domain name.",
                    }
                )
                self._append_unique(
                    entry,
                    "evidence",
                    [
                        "Local session: developer pattern check"
                        if developer_check
                        else f"Local session: violation {', '.join(violations or [])}"
                    ],
                    30,
                )
                self._append_unique(entry, "appContexts", [app_context], 20)
                changed = True
            if changed and persist:
                self._save_locked()
    def apply_ai_verdict(
        self,
        domain: str,
        verdict: dict[str, Any],
        *,
        record_history: bool = True,
    ) -> dict[str, Any] | None:
        """The AI review verdict relies on a single domain.

        The verdict is always fully saved in `aiVerdict`, because the review opinion is useful information
        even when it does not change the color. Color changes have three limits: the catalog"]
        Reviewed items are not revoked, and locally pinned red items are not downloaded, and `blockSafe`
        only becomes true if the local engine agrees that the path is not functional—
        blocking must not break the application.
        """
        clean = _normalize_domain(domain)
        if not clean or not isinstance(verdict, dict):
            return None
        color = str(verdict.get("color") or "")
        if color not in RISK_ORDER or color == "unclassified":
            return None

        with self.lock:
            entry = self.data["domains"].get(clean) or self._new_entry(clean)
            self.data["domains"][clean] = entry
            previous = str(entry.get("risk") or "unclassified")
            catalog = _catalog_for_domain(clean)
            local_red = previous == "red" and any(
                str(item).startswith("Local session:") for item in entry.get("evidence", [])
            )
            stored = dict(verdict)
            # Blocking gateway: requires both model verdict and local engine permission, not just one.
            # The model's verdict is stored separately in `modelBlockSafe`, otherwise the gateway clears it
            # so the scope does not return to the list when permission is expanded later.
            callers = tuple(
                str(item) for item in (entry.get("appBundles") or []) if item
            ) + tuple(str(item) for item in (entry.get("appContexts") or []) if item)
            allowed, veto = ai_block_gate(clean, str(entry.get("category") or ""), callers)
            model_says = verdict.get("modelBlockSafe")
            if model_says is None:
                model_says = verdict.get("blockSafe")
            stored["modelBlockSafe"] = bool(model_says)
            stored["localBlockSafe"] = allowed
            stored["blockVeto"] = "" if allowed else veto
            stored["blockSafe"] = bool(model_says) and allowed
            if catalog:
                stored["applied"] = False
                stored["appliedReason"] = "Reviewed catalog overrides review judgment"
            elif local_red and RISK_ORDER[color] < RISK_ORDER["red"]:
                stored["applied"] = False
                stored["appliedReason"] = "Locally pinned red item not downloaded by model rule"
            else:
                stored["applied"] = True
                stored["appliedReason"] = ""
            entry["aiVerdict"] = stored
            entry["aiReviewedAt"] = str(stored.get("reviewedAt") or _now_iso())

            changed = False
            if stored["applied"]:
                entry["risk"] = color
                entry["riskLabel"] = RISK_LABELS[color]
                entry["stage"] = "studied"
                entry["stageLabel"] = STAGE_LABELS["studied"]
                entry["confidence"] = max(0, min(100, int(stored.get("confidence") or 0)))
                entry["confidenceLabel"] = (
                    "High confidence" if entry["confidence"] >= 80
                    else "Medium confidence" if entry["confidence"] >= 50
                    else "Preliminary confidence"
                )
                if stored.get("category"):
                    entry["categoryLabel"] = _bounded(stored["category"], 80)
                if stored.get("purpose"):
                    entry["summary"] = _bounded(stored["purpose"], 300)
                if stored.get("reason"):
                    entry["reason"] = _bounded(stored["reason"], 300)
                entry["privacyRelevant"] = color == "red"
                entry["deviceDataAccess"] = bool(stored.get("collects")) or color == "red"
                entry["analyzedAt"] = entry["aiReviewedAt"]
                reviewers = ", ".join(
                    str(name) for name in (stored.get("reviewers") or []) if name
                ) or str(stored.get("provider") or "")
                self._append_unique(
                    entry,
                    "evidence",
                    [f"AI Review ({reviewers}): {stored.get('agreement', '')}".strip()],
                    30,
                )
                if previous != color:
                    changed = True
                if record_history and previous != color:
                    history = entry.get("classificationHistory")
                    if not isinstance(history, list):
                        history = []
                    history.append(
                        {
                            "from": previous,
                            "to": color,
                            "at": entry["aiReviewedAt"],
                            "ruleset": CLASSIFICATION_RULESET_VERSION,
                            "reason": f"AI Review: {_bounded(stored.get('reason'), 160)}",
                        }
                    )
                    entry["classificationHistory"] = history[-20:]
                    entry["reclassifiedAt"] = entry["aiReviewedAt"]
            self._mark_dirty_locked()
            return {
                "changed": changed,
                "applied": stored["applied"],
                "from": previous,
                "to": entry["risk"],
                "verdict": stored,
            }

    def ai_review_summary(self) -> dict[str, Any]:
        """Count reviewed and changed items for display in the UI without scanning the entire file."""
        with self.lock:
            reviewed = 0
            applied = 0
            disagreements = 0
            blockable = 0
            colors = {"green": 0, "orange": 0, "red": 0}
            for entry in self.data["domains"].values():
                verdict = entry.get("aiVerdict") if isinstance(entry, dict) else None
                if not isinstance(verdict, dict) or not verdict.get("color"):
                    continue
                reviewed += 1
                colors[verdict["color"]] = colors.get(verdict["color"], 0) + 1
                if verdict.get("applied"):
                    applied += 1
                if verdict.get("agreement") == "Disagreement":
                    disagreements += 1
                if verdict["color"] == "red" and verdict.get("blockSafe"):
                    blockable += 1
            return {
                "reviewed": reviewed,
                "applied": applied,
                "colors": colors,
                "disagreements": disagreements,
                "blockRecommended": blockable,
                "total": len(self.data["domains"]),
            }

    def bootstrap(
        self,
        policy: dict[str, Any],
        profiles: dict[str, Any],
        activity: list[dict[str, Any]],
        controls: dict[str, Any] | None = None,
        privacy_domains_by_bundle: dict[str, dict[str, str] | list[str] | set[str]] | None = None,
        developer_domains_by_bundle: dict[str, list[str] | set[str]] | None = None,
    ) -> None:
        app_domains_by_bundle: dict[str, set[str]] = {}
        for domain, settings in policy.get("domains", {}).items():
            self.observe(
                domain,
                decision=str(settings.get("action", "")),
                label=str(settings.get("label", "")),
                note=str(settings.get("note", "")),
                schedule=False,
                persist=False,
            )
        for app in list(profiles.get("apps", [])) + list(profiles.get("detectedApps", [])):
            context = str(app.get("name") or app.get("bundleID") or "")
            observed_at = str(app.get("lastSeen") or "")
            domains = set(app.get("confirmedDomains", [])) | set(app.get("observedDomains", [])) | set(app.get("domains", []))
            bundle = str(app.get("bundleID") or "").lower()
            if bundle:
                app_domains_by_bundle.setdefault(bundle, set()).update(
                    _normalize_domain(domain) for domain in domains if _normalize_domain(domain)
                )
            for domain in domains:
                self.observe(
                    domain,
                    app_context=context,
                    app_bundle=bundle,
                    observed_at=observed_at,
                    schedule=False,
                    persist=False,
                )
        for item in activity:
            self.observe(
                str(item.get("domain", "")),
                qtype=str(item.get("qtypeName", "")),
                transport=str(item.get("transport", "")),
                decision=str(item.get("decision", "")),
                cname_chain=list(item.get("cnameChain", []) or []),
                observed_at=str(item.get("time", "")),
                schedule=False,
                persist=False,
            )
        for bundle_id, control in (controls or {}).get("apps", {}).items():
            bundle_key = str(bundle_id).lower()
            result = control.get("lastResult", {})
            containment = result.get("containment", {})
            blocked = list(containment.get("blockedDomains", []) or [])
            violations = list(containment.get("violations", []) or [])
            if not violations:
                violations = [
                    key
                    for key, value in (control.get("evaluation", {}) or {}).items()
                    if isinstance(value, dict) and value.get("verdict") == "violation"
                ]
            developer = bool(result.get("developerChecks", {}).get("detected"))
            mapped_privacy = (privacy_domains_by_bundle or {}).get(bundle_key, {})
            if isinstance(mapped_privacy, dict):
                mapped_privacy = list(mapped_privacy)
            privacy_domains = blocked or list(mapped_privacy or [])
            if not privacy_domains and violations:
                privacy_domains = [
                    domain
                    for domain in app_domains_by_bundle.get(bundle_key, set())
                    if (_catalog_for_domain(domain) or {}).get("risk") == "red"
                ]
            if privacy_domains and violations:
                self.mark_privacy_evidence(
                    privacy_domains,
                    violations=violations,
                    developer_check=False,
                    app_context=str(control.get("appName") or bundle_id),
                    persist=False,
                )
            developer_domains = list(
                (developer_domains_by_bundle or {}).get(bundle_key, []) or []
            )
            if not developer_domains and developer:
                developer_domains = [
                    domain
                    for domain in app_domains_by_bundle.get(bundle_key, set())
                    if (_catalog_for_domain(domain) or {}).get("developerModeCheck")
                ]
            if developer and developer_domains:
                self.mark_privacy_evidence(
                    developer_domains,
                    violations=[],
                    developer_check=True,
                    app_context=str(control.get("appName") or bundle_id),
                    persist=False,
                )
        with self.lock:
            self._save_locked()

    def start(self) -> None:
        if (
            self.classification_paused
            or not self.active_analysis
            or any(worker.is_alive() for worker in self.workers)
        ):
            return
        self.workers = [
            threading.Thread(target=self._worker_loop, name=f"domain-study-v3-{index}", daemon=True)
            for index in range(1, BACKGROUND_ANALYSIS_WORKERS + 1)
        ]
        for worker in self.workers:
            worker.start()
        # New non-catalog domains receive a preliminary color immediately and are
        # upgraded by the bounded public HTTPS study when observation schedules it.

    def shutdown(self) -> None:
        self.stopping.set()
        self._flush_wake.set()
        for _ in self.workers:
            self.jobs.put(None)
        for worker in self.workers:
            worker.join(timeout=2)
        flusher = self._flusher
        if flusher is not None and flusher.is_alive():
            flusher.join(timeout=2)
        self.flush()

    def schedule(self, domain: str, force: bool = False) -> bool:
        if self.classification_paused:
            return False
        clean = _normalize_domain(domain)
        if not clean:
            return False
        with self.lock:
            entry = self.data["domains"].get(clean)
            if not entry:
                entry = self._new_entry(clean)
                self.data["domains"][clean] = entry
                self._mark_dirty_locked()
            if not force and entry.get("stage") == "studied":
                return False
            if clean in self.pending:
                return False
            self.pending.add(clean)
        self.jobs.put(clean)
        return True

    def request_analysis(
        self,
        domain: str = "",
        force: bool = False,
        limit: int | None = None,
    ) -> dict[str, Any]:
        if self.classification_paused:
            return {
                "ok": False,
                "queued": 0,
                "pending": 0,
                "classificationPaused": True,
                "message": "Classification deferred until the new plan is approved.",
            }
        if domain:
            queued = 1 if self.schedule(domain, force=force) else 0
        else:
            with self.lock:
                candidates = list(self.data["domains"].items())
            if not force:
                candidates = [
                    item for item in candidates if item[1].get("stage") != "studied"
                ]
            candidates.sort(
                key=lambda item: (
                    bool(item[1].get("lastProbeAt")),
                    -RISK_ORDER.get(str(item[1].get("risk")), 0),
                    -int(item[1].get("hits", 0)),
                    str(item[1].get("lastProbeAt", "")),
                    item[0],
                )
            )
            domains = [item[0] for item in candidates]
            if limit is not None:
                domains = domains[: max(0, int(limit))]
            queued = sum(1 for item in domains if self.schedule(item, force=force))
        return {"ok": True, "queued": queued, "pending": self.jobs.qsize()}

    def _worker_loop(self) -> None:
        while not self.stopping.is_set():
            domain = self.jobs.get()
            if domain is None:
                break
            try:
                self.analyze(domain)
            except Exception:
                # A single untrusted endpoint must never stop DNS or later studies.
                pass
            finally:
                with self.lock:
                    self.pending.discard(domain)
                self.jobs.task_done()
            time.sleep(0.15)

    def analyze(self, domain: str) -> dict[str, Any] | None:
        clean = _normalize_domain(domain)
        if not clean:
            return None
        if self.classification_paused:
            return self.get(clean)
        study = self.probe.study(clean)
        with self.lock:
            entry = self.data["domains"].get(clean) or self._new_entry(clean)
            self.data["domains"][clean] = entry
            entry["lastProbeAt"] = _now_iso()
            entry["networkStudy"] = study
            inferred = self._apply_network_study_locked(clean, entry, study)
            for bundle in list(entry.get("appBundles", []) or []):
                self._apply_app_purpose_locked(clean, entry, str(bundle))
            self._apply_shared_sdk_evidence_locked(clean, entry, inferred)
            self._mark_dirty_locked()
            return json.loads(json.dumps(entry, ensure_ascii=False))

    def get(self, domain: str) -> dict[str, Any] | None:
        clean = _normalize_domain(domain)
        with self.lock:
            entry = self.data["domains"].get(clean)
            return json.loads(json.dumps(entry, ensure_ascii=False)) if entry else None

    def summary(self) -> dict[str, Any]:
        with self.lock:
            entries = list(self.data["domains"].values())
            colors = {
                risk: sum(1 for item in entries if item.get("risk") == risk)
                for risk in ("unclassified", "green", "orange", "red")
            }
            stages = {
                stage: sum(1 for item in entries if item.get("stage") == stage)
                for stage in STAGE_LABELS
            }
            return {
                "version": ENGINE_VERSION,
                "engine": "DNS Engine V3",
                "classificationRuleset": CLASSIFICATION_RULESET_VERSION,
                "total": len(entries),
                "colors": colors,
                "stages": stages,
                "pending": len(self.pending),
                "activeAnalysis": self.active_analysis and not self.classification_paused,
                "classificationPaused": self.classification_paused,
            }

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "version": ENGINE_VERSION,
                "engine": "DNS Engine V3",
                "definitions": {
                    "unclassified": RISK_LABELS["unclassified"],
                    "green": RISK_LABELS["green"],
                    "orange": RISK_LABELS["orange"],
                    "red": RISK_LABELS["red"],
                    "new": "Newly observed domain, not yet classified or studied.",
                },
                "summary": self.summary(),
                "domains": json.loads(json.dumps(self.data["domains"], ensure_ascii=False)),
            }
