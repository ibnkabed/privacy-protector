"use strict";

const operationTrayStorageKey = "privacy-protector-operation-tray-v2";

function loadOperationTray() {
  try {
    const stored = window.localStorage.getItem(operationTrayStorageKey);
    if (stored === null) return new Set();
    const domains = JSON.parse(stored);
    if (!Array.isArray(domains)) return null;
    return new Set(
      domains
        .map((value) => String(value || "").trim().toLowerCase().replace(/\.$/, ""))
        .filter((value) => value.includes(".") && !value.startsWith("function:"))
    );
  } catch {
    return new Set();
  }
}

const state = {
  reportRows: [],
  filteredRows: [],
  policy: { domains: {} },
  viewMode: "live",
  profiles: [],
  detectedApps: [],
  liveCursor: 0,
  recentItems: [],
  attributions: [],
  domainStats: {},
  dnsEngine: null,
  appAttribution: null,
  classifications: {
    summary: { total: 0, colors: { green: 0, orange: 0, red: 0 }, stages: { preliminary: 0, studied: 0 }, pending: 0 },
    domains: {},
  },
  operationTray: {
    domains: loadOperationTray(),
    filter: "",
    sort: "time",
  },
  expandedSharedDomains: new Set(),
  rowSort: "time",
  session: {
    active: false,
    startedAfterId: 0,
    appId: "",
    appName: "",
    items: new Map(),
  },
  privacy: {
    apps: {},
    defaults: {
      location: "deny",
      motion: "deny",
      tracking: "deny",
      systemState: "monitor",
      containment: "monitor",
    },
    capture: { active: false },
    incidents: [],
    desired: {
      location: "deny",
      motion: "deny",
      tracking: "deny",
      systemState: "monitor",
      containment: "monitor",
    },
  },
};

const knownAppNames = {};

const el = (id) => document.getElementById(id);

function normalizeDomain(value) {
  return String(value || "").trim().toLowerCase().replace(/\.$/, "");
}

function isTracker(domain) {
  const clean = normalizeDomain(domain);
  return domainPrivacyProfile(clean).privacyRelevant;
}

function isTrackingRow(row) {
  return Number(row.domainType) === 1 || domainPrivacyProfile(row.domain).privacyRelevant;
}

function baseDomain(value) {
  const parts = normalizeDomain(value).split(".").filter(Boolean);
  return parts.length > 1 ? parts.slice(-2).join(".") : parts.join(".");
}

function domainPrivacyProfile(domain) {
  const clean = normalizeDomain(domain);
  const studied = state.classifications.domains?.[clean];
  if (studied) {
    const risk = ["green", "orange", "red"].includes(studied.risk) ? studied.risk : "green";
    const stage = studied.stage === "studied" ? "studied" : "preliminary";
    return {
      key: `risk-${risk}`,
      risk,
      label: studied.categoryLabel || studied.riskLabel || "General network service",
      note: studied.reason || studied.summary || "DNS Engine V3 classification",
      summary: studied.summary || "",
      stage,
      stageLabel: studied.stageLabel || (stage === "studied" ? "Studied" : "Preliminary"),
      confidence: Number(studied.confidence) || 0,
      confidenceLabel: studied.confidenceLabel || "Preliminary confidence",
      privacyRelevant: risk === "red",
      developerModeCheck: Boolean(studied.developerModeCheck),
      deviceDataAccess: Boolean(studied.deviceDataAccess),
      evidence: Array.isArray(studied.evidence) ? studied.evidence : [],
    };
  }
  const policy = state.policy.domains?.[clean] || {};
  const text = `${clean} ${policy.label || ""} ${policy.note || ""}`.toLowerCase();
  const preliminary = (risk, label, note, confidence) => ({
    key: `risk-${risk}`,
    risk,
    label,
    note,
    summary: note,
    stage: "preliminary",
    stageLabel: "Preliminary",
    confidence,
    confidenceLabel: confidence >= 50 ? "Medium confidence" : "Preliminary confidence",
    privacyRelevant: risk === "red",
    developerModeCheck: /developer.?mode|jailbreak|root.?check|integrity/.test(text),
    deviceDataAccess: risk !== "green",
    evidence: ["Immediate hostname classification"],
  });
  if (/(analytics|measurement|tracking|tracker|doubleclick|adsystem|appsflyer|adjust|rudderstack|clarity|demdex|tagmanager|devicecheck|appattest|developer.?mode|jailbreak|root.?check|integrity|location|motion|fitness|health)/.test(text)) {
    return preliminary("red", "Tracking or privacy signal", "The hostname contains a tracking or privacy-check signal; V3 study is pending.", 64);
  }
  if (/(crash|logging|diagnostic|telemetry|performance|push|messaging|notification|device|installation|instance|sentry|appcenter|optimization|siri)/.test(text)) {
    return preliminary("orange", "Operational device data", "The service appears diagnostic or operational and may use device attributes without a confirmed violation.", 56);
  }
  if (/(auth|oauth|login|api|gateway|cdn|asset|static|font|image|privacy|relay|safebrowsing|cookie|account|update)/.test(text)) {
    return preliminary("green", "Functional service", "The hostname indicates authentication, an API, assets, or a protection service.", 52);
  }
  return preliminary("green", "General network service", "The hostname has no direct privacy signal; a V3 study was scheduled automatically.", 35);
}

function classify(row) {
  return domainPrivacyProfile(row.domain);
}

function operationKeyForRow(row) {
  return normalizeDomain(row.domain);
}

function operationKey(value) {
  return normalizeDomain(value);
}

function localTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  }).format(date);
}

function localDateTime(value) {
  if (!value) return "Not observed yet";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Not observed yet";
  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  }).format(date);
}

function rowLastObservedAt(row) {
  const classificationTime = state.classifications.domains?.[normalizeDomain(row.domain)]?.lastObservedAt
    || "";
  const candidates = [row.timeStamp, classificationTime]
    .map((value) => ({ value, time: Date.parse(value) }))
    .filter((item) => Number.isFinite(item.time));
  candidates.sort((a, b) => b.time - a.time);
  return candidates[0]?.value || "";
}

function cleanApplicationName(value) {
  const clean = String(value || "").trim();
  if (!clean || /^(?:Saved evidence|Shared hostname|Local evidence|Device\s)/.test(clean)) return "";
  return clean;
}

function applicationNamesForDomain(domain) {
  const clean = normalizeDomain(domain);
  const names = new Set();
  for (const profile of state.profiles) {
    if (profileDomains(profile).has(clean)) names.add(profile.name || profile.bundleID);
  }
  for (const app of detectedAppsForDomain(clean)) {
    names.add(app.name || knownAppNames[String(app.bundleID || "").toLowerCase()] || app.bundleID);
  }
  for (const context of state.classifications.domains?.[clean]?.appContexts || []) {
    const name = cleanApplicationName(context);
    if (name) names.add(name);
  }
  return [...names].filter(Boolean);
}

function applicationNameForRow(row) {
  return applicationIdentityForRow(row).label;
}

function attributionSourceLabel(source, confidence = "") {
  if (source === "ios-pcap") {
    return confidence === "exact-process-unmapped"
      ? "Observed iOS process; no matching display name"
      : "Exact attribution from iOS process metadata over USB";
  }
  if (source === "app-privacy-report") return "Confirmed attribution from an Apple App Privacy Report";
  if (source === "ios-syslog") return "Local evidence from an iOS log";
  if (source === "profile") return "Saved application-profile evidence";
  return "Saved application evidence";
}

function applicationIdentityForRow(row) {
  const names = new Set();
  const sources = new Set();
  const directBundle = String(row.bundleID || "").trim();
  if (directBundle.includes(".")) {
    const detected = state.detectedApps.find(
      (app) => String(app.bundleID || "").toLowerCase() === directBundle.toLowerCase()
    );
    names.add(detected?.name || knownAppNames[directBundle.toLowerCase()] || directBundle);
    if (row.type === "networkActivity" && row.coverageState === "report") {
      sources.add(attributionSourceLabel("app-privacy-report", "exact-bundle"));
    }
  }
  for (const app of row.applications || []) {
    const appName = cleanApplicationName(app.name || app.bundleID);
    if (appName) names.add(appName);
    sources.add(attributionSourceLabel("app-privacy-report", "exact-bundle"));
  }
  const domain = normalizeDomain(row.domain);
  for (const event of state.attributions) {
    if (event.type !== "appDomain" || normalizeDomain(event.domain) !== domain) continue;
    const eventName = cleanApplicationName(event.appName || event.processName);
    if (eventName) names.add(eventName);
    sources.add(attributionSourceLabel(event.source, event.confidence));
  }
  const supplied = cleanApplicationName(row.context);
  if (supplied) {
    names.add(supplied);
    sources.add(row.coverageState === "report"
      ? attributionSourceLabel("app-privacy-report")
      : attributionSourceLabel("profile"));
  }
  const bundle = cleanApplicationName(row.bundleID);
  if (bundle && bundle.includes(".")) names.add(knownAppNames[bundle.toLowerCase()] || bundle);
  for (const name of applicationNamesForDomain(row.domain)) {
    names.add(name);
    sources.add(attributionSourceLabel("profile"));
  }
  const visibleNames = [...names].filter(Boolean);
  return {
    label: visibleNames.length > 1
      ? "+ Applications"
      : visibleNames[0] || "Unattributed - DNS only",
    names: visibleNames,
    source: [...sources].filter(Boolean).join(" • ")
      || "A DNS request does not include an application name; USB metadata or an Apple report is required for attribution",
    attributed: visibleNames.length > 0,
  };
}

function rowTypeLabel(row) {
  const qtypes = state.classifications.domains?.[normalizeDomain(row.domain)]?.qtypes || [];
  return qtypes.length ? `DNS ${qtypes.join("/")}` : "hostname";
}

function dateSpan(rows) {
  const times = rows
    .map((row) => new Date(row.timeStamp).getTime())
    .filter(Number.isFinite)
    .sort((a, b) => a - b);
  if (!times.length) return "No timing available";
  const duration = Math.max(0, Math.round((times.at(-1) - times[0]) / 1000));
  return `Report duration: ${duration} seconds`;
}

function mergeDomainStats(items) {
  for (const item of items || []) {
    const domain = normalizeDomain(item.domain);
    if (!domain) continue;
    const current = state.domainStats[domain] || {
      observedCount: 0,
      blockedCount: 0,
      lastObservedAt: "",
      lastBlockedAt: "",
      lastAction: "",
    };
    const observedAt = String(item.time || "");
    current.observedCount += 1;
    if ((Date.parse(observedAt) || 0) >= (Date.parse(current.lastObservedAt) || 0)) {
      current.lastObservedAt = observedAt;
      current.lastAction = String(item.action || "");
    }
    if (item.action === "blocked") {
      current.blockedCount += 1;
      if ((Date.parse(observedAt) || 0) >= (Date.parse(current.lastBlockedAt) || 0)) {
        current.lastBlockedAt = observedAt;
      }
    }
    state.domainStats[domain] = current;
  }
}

function toast(message, error = false) {
  const box = document.createElement("div");
  box.className = `toast${error ? " error" : ""}`;
  box.textContent = message;
  document.body.appendChild(box);
  setTimeout(() => box.remove(), 3100);
}

async function refreshProfiles(preferredId = "") {
  const response = await fetch("/api/apps", { cache: "no-store" });
  if (!response.ok) throw new Error("Unable to load saved applications");
  const data = await response.json();
  state.profiles = Array.isArray(data.apps) ? data.apps : [];
  state.detectedApps = Array.isArray(data.detectedApps) ? data.detectedApps : [];
  updateAppMetric();
  renderProfiles(preferredId);
  renderBundleSuggestions();
  renderDetectedApps();
}

function renderProfiles(preferredId = "") {
  const select = el("appProfile");
  const selected = preferredId || select.value;
  select.replaceChildren();
  const allOption = document.createElement("option");
  allOption.value = "";
  allOption.textContent = "All applications";
  allOption.title = "Show activity and actions for all applications";
  select.appendChild(allOption);
  for (const profile of state.profiles) {
    const option = document.createElement("option");
    option.value = profile.id;
    option.textContent = profile.name;
    const known = new Set([
      ...(profile.confirmedDomains || []),
      ...(profile.observedDomains || []),
    ]).size;
    option.title = profile.bundleID
      ? `${profile.bundleID} — ${known} saved hostnames`
      : `${known} saved hostnames`;
    select.appendChild(option);
  }
  if (state.profiles.some((profile) => profile.id === selected)) {
    select.value = selected;
  } else {
    select.value = "";
  }
  updateSelectedAppControls();
  applyFilter(false);
  renderPolicy();
}

function selectedAppProfile() {
  return state.profiles.find((profile) => profile.id === el("appProfile").value) || null;
}

function profileDomains(profile) {
  if (!profile) return new Set();
  return new Set(
    [...(profile.confirmedDomains || []), ...(profile.observedDomains || [])]
      .map(normalizeDomain)
      .filter(Boolean)
  );
}

function knownDomainsForView(profile = selectedAppProfile()) {
  const domains = new Set();
  if (profile) {
    for (const domain of profileDomains(profile)) domains.add(domain);
    const profileBundle = String(profile.bundleID || "").toLowerCase();
    for (const app of state.detectedApps) {
      if (profileBundle && String(app.bundleID || "").toLowerCase() === profileBundle) {
        for (const domain of app.domains || []) domains.add(normalizeDomain(domain));
      }
    }
  } else {
    for (const item of state.profiles) {
      for (const domain of profileDomains(item)) domains.add(domain);
    }
    for (const app of state.detectedApps) {
      for (const domain of app.domains || []) domains.add(normalizeDomain(domain));
    }
    for (const domain of Object.keys(state.policy.domains || {})) domains.add(domain);
    for (const domain of Object.keys(state.classifications.domains || {})) domains.add(domain);
    for (const item of state.recentItems) domains.add(normalizeDomain(item.domain));
    for (const item of state.reportRows) domains.add(normalizeDomain(item.domain));
  }
  return new Set([...domains].filter((domain) => domain && domain.includes(".")));
}

function coverageChip(text, tone = "unknown") {
  const chip = document.createElement("span");
  chip.className = `coverage-chip ${tone}`;
  chip.textContent = text;
  return chip;
}

function renderCoverageStrips() {
  const profile = selectedAppProfile();
  const domains = knownDomainsForView(profile);
  const risks = { green: 0, orange: 0, red: 0 };
  let studiedCount = 0;
  for (const domain of domains) {
    const rating = domainPrivacyProfile(domain);
    risks[rating.risk] = (risks[rating.risk] || 0) + 1;
    if (rating.stage === "studied") studiedCount += 1;
  }

  const activityBox = el("activityCoverage");
  activityBox.replaceChildren();
  if (profile?.purposeRisk) {
    activityBox.append(coverageChip(
      `${profile.name}: ${profile.purposeLabel} — ${profile.purposeReason}`,
      `risk-${profile.purposeRisk}`
    ));
  }
  activityBox.append(
    coverageChip(`${domains.size} permanent hostnames`, "network"),
    coverageChip(`${risks.red} red`, "risk-red"),
    coverageChip(`${risks.orange} orange`, "risk-orange"),
    coverageChip(`${risks.green} green`, "risk-green"),
    coverageChip(`${studiedCount}/${domains.size} Studied`, studiedCount === domains.size ? "protected" : "unknown")
  );

  const attribution = state.appAttribution || {};
  const packetState = attribution.packetAttribution?.state || "unavailable";
  const attributedApps = Number(attribution.summary?.attributedApps) || 0;
  activityBox.append(coverageChip(
    packetState === "listening"
      ? `Application names: USB attribution active • ${attributedApps} applications`
      : packetState === "paused"
        ? "All hostnames that reach this resolver are monitored continuously"
      : attributedApps
        ? `Application names: ${attributedApps} from saved evidence • USB is not connected`
        : "Application names: connect USB for exact attribution",
    packetState === "listening"
      ? "protected"
      : packetState === "paused"
        ? "protected"
      : attributedApps
        ? "observed"
        : "unknown"
  ));

  const operationsBox = el("operationsCoverage");
  operationsBox.replaceChildren();
  const trayDomains = [...state.operationTray.domains];
  const actionCounts = { block: 0, monitor: 0, allow: 0, pending: 0 };
  for (const domain of trayDomains) {
    const action = state.policy.domains?.[domain]?.action;
    if (action in actionCounts) actionCounts[action] += 1;
    else actionCounts.pending += 1;
  }
  operationsBox.append(
    coverageChip(`${trayDomains.length} hostnames in actions`, "network"),
    coverageChip(`${actionCounts.pending} waiting for a decision`, actionCounts.pending ? "observed" : "protected"),
    coverageChip(`${actionCounts.block} blocked`, actionCounts.block ? "risk-red" : "unknown"),
    coverageChip(`${actionCounts.monitor} monitored`, actionCounts.monitor ? "risk-orange" : "unknown"),
    coverageChip(`${actionCounts.allow} allowed`, actionCounts.allow ? "risk-green" : "unknown")
  );

  const engine = state.dnsEngine;
  if (!engine) return;
  const udp = engine.transports?.udp || {};
  const tcp = engine.transports?.tcp || {};
  const providers = engine.providers || [];
  const primary = providers.find((item) => item.role === "primary") || {};
  const fallback = providers.find((item) => item.role === "fallback") || {};
  const iphone = engine.iphoneClient || {};
  const providerCount = [primary, fallback].filter((item) => item.state === "healthy").length;
  const iphoneText = iphone.state === "confirmed" ? "iPhone connected"
    : iphone.state === "possibleClient" ? "unattributed device connection"
      : "iPhone not detected";
  const engineHealthy = udp.received && tcp.received && providerCount === 2;
  activityBox.append(coverageChip(
    `DNS: UDP ${udp.received ? "✓" : "—"} • TCP ${tcp.received ? "✓" : "—"} • DoH ${providerCount}/2 • ${iphoneText}`,
    engineHealthy ? "protected" : providerCount === 0 ? "violation" : "observed"
  ));
}

async function runDNSSelfTest() {
  try {
    const response = await fetch("/api/dns/self-test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    const result = await response.json();
    await refreshStatus();
    const passed = (result.checks || []).filter((item) => item.state === "passed").length;
    const total = (result.checks || []).length;
    toast(result.state === "passed" ? `DNS self-test passed: ${passed}/${total}` : `DNS self-test incomplete: ${passed}/${total}`, result.state !== "passed");
  } catch {
    toast("Unable to run the DNS self-test", true);
  }
}

function rowBelongsToProfile(row, profile) {
  if (!profile) return true;
  const rowBundle = String(row.bundleID || "").trim().toLowerCase();
  const profileBundle = String(profile.bundleID || "").trim().toLowerCase();
  if (profileBundle && rowBundle === profileBundle) return true;
  if (row.profileID && row.profileID === profile.id) return true;
  return profileDomains(profile).has(normalizeDomain(row.domain));
}

function detectedAppsForDomain(domain) {
  const clean = normalizeDomain(domain);
  return state.detectedApps.filter((app) =>
    (app.domains || []).some((item) => normalizeDomain(item) === clean)
  );
}

function updateSelectedAppControls() {
  const locked = state.session.active;
  if (!locked) el("appProfile").disabled = false;
  if (locked) el("appProfile").disabled = true;
  updateAppMetric();
  renderCoverageStrips();
}

function addAppProfile() {
  el("appForm").reset();
  renderBundleSuggestions();
  el("appDialog").showModal();
  setTimeout(() => el("appName").focus(), 0);
}

function renderBundleSuggestions() {
  const list = el("bundleSuggestions");
  list.replaceChildren();
  for (const app of state.detectedApps) {
    const option = document.createElement("option");
    option.value = app.bundleID;
    option.label = `${app.bundleID} — ${app.domains.length} hostname`;
    list.appendChild(option);
  }
}

function detectedName(bundleID, row = {}) {
  const supplied = String(
    row.appName || row.displayName || row.applicationName || ""
  ).trim();
  return supplied || knownAppNames[bundleID.toLowerCase()] || bundleID;
}

function renderDetectedApps() {
  const list = el("detectedAppsList");
  if (!list) return;
  const query = String(el("detectedSearch")?.value || "").trim().toLowerCase();
  const visible = state.detectedApps.filter((app) =>
    `${app.name} ${app.bundleID}`.toLowerCase().includes(query)
  );
  el("detectedCount").textContent = String(state.detectedApps.length);
  list.replaceChildren();
  if (!visible.length) {
    const empty = document.createElement("p");
    empty.className = "detected-empty";
    empty.textContent = state.detectedApps.length
      ? "No applications match the search."
      : "Import an Apple report to discover applications.";
    list.appendChild(empty);
    return;
  }
  for (const app of visible) {
    const item = document.createElement("article");
    item.className = "detected-app";
    const info = document.createElement("div");
    info.className = "detected-app-info";
    const name = document.createElement("strong");
    name.textContent = app.purposeDisplayName || app.name || app.bundleID;
    const bundle = document.createElement("code");
    bundle.textContent = app.bundleID;
    const summary = document.createElement("small");
    const sources = Array.isArray(app.sources) ? app.sources : ["report"];
    const sourceLabel = sources.includes("device")
      ? "From paired-iPhone inventory"
      : "From Apple report";
    const processLabel = app.processName ? ` — Process: ${app.processName}` : "";
    summary.textContent = `${(app.domains || []).length} hostname — ${sourceLabel}${processLabel}`;
    const purpose = document.createElement("small");
    if (app.purposeRisk) {
      purpose.className = `policy-classification risk-${app.purposeRisk}`;
      purpose.textContent = `${app.purposeLabel} — ${app.purposeReason}`;
    }
    info.append(name);
    if (app.purposeRisk) info.append(purpose);
    info.append(bundle, summary);
    const added = state.profiles.some(
      (profile) =>
        profile.bundleID &&
        profile.bundleID.toLowerCase() === app.bundleID.toLowerCase()
    );
    const button = document.createElement("button");
    button.type = "button";
    button.className = "detected-add";
    button.textContent = added ? "Added to monitoring" : "Add to monitoring";
    button.disabled = added;
    button.addEventListener("click", () => addDetectedApp(app));
    item.append(info, button);
    list.appendChild(item);
  }
}

async function addDetectedApp(app) {
  try {
    const response = await fetch("/api/apps", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: app.purposeDisplayName || app.name || app.bundleID,
        bundleID: app.bundleID,
        processName: app.processName || "",
      }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Unable to add the application");
    if ((app.domains || []).length) {
      const linkResponse = await fetch(
        `/api/apps/${encodeURIComponent(result.profile.id)}/domains`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ source: "confirmed", domains: app.domains }),
        }
      );
      if (!linkResponse.ok) throw new Error("The application was added without linking hostnames");
    }
    await refreshProfiles(result.profile.id);
    toast(`Added ${result.profile.name} to monitoring`);
  } catch (error) {
    toast(error.message, true);
  }
}

async function scanIPhoneApps() {
  const button = el("scanIPhoneApps");
  const status = el("deviceScanStatus");
  button.disabled = true;
  status.textContent = "Reading the local paired-iPhone application list...";
  try {
    const response = await fetch("/api/device/apps/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Unable to read the application inventory");
    await refreshProfiles(el("appProfile").value);
    status.textContent = `Read ${result.count} applications from the iPhone`;
    toast(`Detected ${result.count} installed applications`);
  } catch (error) {
    status.textContent = error.message;
    toast(error.message, true);
  } finally {
    button.disabled = false;
  }
}

async function saveAppProfile(event) {
  event.preventDefault();
  const name = el("appName").value.trim();
  const bundleID = el("appBundleID").value.trim();
  const processName = el("appProcessName").value.trim();
  if (!name) return;
  try {
    const response = await fetch("/api/apps", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, bundleID, processName }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Unable to save the application");
    el("appDialog").close();
    await refreshProfiles(result.profile.id);
    toast(`Added ${result.profile.name}`);
  } catch (error) {
    toast(error.message, true);
  }
}

async function deleteAppProfile() {
  const profile = state.profiles.find((item) => item.id === el("appProfile").value);
  if (!profile || state.session.active) return;
  if (!window.confirm(`Remove '${profile.name}' from the local review list?`)) return;
  try {
    const response = await fetch(`/api/apps/${encodeURIComponent(profile.id)}`, {
      method: "DELETE",
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Unable to remove the application");
    await refreshProfiles();
    toast(`Removed ${profile.name}`);
  } catch (error) {
    toast(error.message, true);
  }
}

async function startScanSession() {
  const profile = state.profiles.find((item) => item.id === el("appProfile").value);
  if (!profile) return;
  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    if (!response.ok) throw new Error("The review service is not ready");
    const status = await response.json();
    state.session.startedAfterId = Number(status.lastEventId) || 0;
  } catch (error) {
    toast(error.message, true);
    return;
  }
  state.session.active = true;
  state.session.appId = profile.id;
  state.session.appName = profile.name;
  state.session.items = new Map();
  state.viewMode = "session";
  state.reportRows = [];
  state.filteredRows = [];
  el("reportName").textContent = `Live session: ${profile.name}`;
  renderRows();
  el("appProfile").disabled = true;
  el("addApp").disabled = true;
  el("deleteApp").disabled = true;
  el("startSession").disabled = true;
  el("stopSession").disabled = false;
  el("sessionTitle").textContent = `Review in progress: ${profile.name}`;
  el("lastActivity").textContent = "Close other applications, then open the application being reviewed";
  toast(`Started review for ${profile.name}`);
}

function captureSessionItems(items) {
  if (!state.session.active) return;
  for (const item of items) {
    const eventId = Number(item.id) || 0;
    if (eventId <= state.session.startedAfterId) continue;
    const domain = normalizeDomain(item.domain);
    if (!domain) continue;
    state.session.items.set(eventId, item);
  }
  el("sessionTitle").textContent =
    `Review in progress: ${state.session.appName} — ${state.session.items.size} connections`;
  renderSessionResults(true);
}

function renderSessionResults(active = false) {
  const items = [...state.session.items.values()].sort(
    (a, b) => Number(b.id) - Number(a.id)
  );
  const domainCounts = new Map();
  for (const item of items) {
    const domain = normalizeDomain(item.domain);
    const current = domainCounts.get(domain);
    if (!current) {
      domainCounts.set(domain, { ...item, hits: 1 });
    } else {
      current.hits += 1;
    }
  }
  state.reportRows = [...domainCounts.values()].map((item) => ({
    type: "networkActivity",
    bundleID: profileBundleForSession(),
    profileID: state.session.appId,
    context: "",
    domain: item.domain,
    domainType: isTracker(item.domain) ? 1 : 2,
    initiatedType: "SessionObserved",
    timeStamp: item.time,
    hits: item.hits,
    action: item.action,
    coverageState: "live",
  }));
  state.filteredRows = [...state.reportRows];
  el("reportName").textContent =
    active
      ? `Connections appearing during the current review of ${state.session.appName}`
      : `Connections observed during the session for ${state.session.appName} — this timing alone does not prove application attribution`;
  updateMetrics(state.reportRows);
  applyFilter();
  return { items, domainCounts };
}

function profileBundleForSession() {
  const profile = state.profiles.find((item) => item.id === state.session.appId);
  return profile?.bundleID || `Session: ${state.session.appName}`;
}

async function stopScanSession() {
  if (!state.session.active) return;
  state.session.active = false;
  const { items, domainCounts } = renderSessionResults(false);
  renderRows();
  el("appProfile").disabled = false;
  el("addApp").disabled = false;
  el("deleteApp").disabled = false;
  el("startSession").disabled = false;
  el("stopSession").disabled = true;
  el("sessionTitle").textContent = `Review completed for ${state.session.appName}`;
  el("lastActivity").textContent =
    `${items.length} DNS requests — ${domainCounts.size} distinct hostnames`;
  if (domainCounts.size) {
    try {
      const response = await fetch(
        `/api/apps/${encodeURIComponent(state.session.appId)}/domains`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            source: "observed",
            domains: [...domainCounts.keys()],
          }),
        }
      );
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "Unable to save review results");
      await refreshProfiles(state.session.appId);
    } catch (error) {
      toast(error.message, true);
      return;
    }
  }
  toast(`Review completed: ${domainCounts.size} hostname`);
}

function parseNDJSON(text) {
  const rows = [];
  let invalid = 0;
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      rows.push(JSON.parse(line));
    } catch {
      invalid += 1;
    }
  }
  return { rows, invalid };
}

function updateMetrics(allRows) {
  const network = allRows.filter((row) => row.type === "networkActivity");
  const domains = new Set(network.map((row) => normalizeDomain(row.domain)).filter(Boolean));
  const red = new Set(network.filter((row) => classify(row).risk === "red").map((row) => normalizeDomain(row.domain)));
  const orange = new Set(network.filter((row) => classify(row).risk === "orange").map((row) => normalizeDomain(row.domain)));

  el("totalRows").textContent = String(allRows.length);
  el("reportWindow").textContent = dateSpan(allRows);
  updateAppMetric();
  el("domainCount").textContent = String(domains.size);
  el("trackerCount").textContent = `red: ${red.size} — orange: ${orange.size}`;
}

function updateAppMetric() {
  const detected = state.detectedApps.length;
  const monitored = state.profiles.length;
  const selected = selectedAppProfile();
  el("appCount").textContent = String(selected ? 1 : monitored);
  el("appInventorySummary").textContent = selected
    ? `Selected: ${selected.name}${selected.purposeLabel ? ` — ${selected.purposeLabel}` : ""}`
    : `View: all — to monitoring: ${monitored}`;
}

function applyFilter() {
  const filter = el("rowFilter").value;
  const profile = selectedAppProfile();
  const scoped = state.reportRows
    .filter((row) => rowBelongsToProfile(row, profile))
    .filter((row) => !operationIsVisible(operationKeyForRow(row)));
  if (["green", "orange", "red"].includes(filter)) {
    state.filteredRows = scoped.filter((row) => classify(row).risk === filter);
  } else if (filter === "managed") {
    state.filteredRows = scoped.filter(
      (row) => Boolean(state.policy.domains?.[normalizeDomain(row.domain)])
    );
  } else {
    state.filteredRows = scoped;
  }
  sortActivityRows();
  renderRows();
}

function sortActivityRows() {
  const riskOrder = { red: 0, orange: 1, green: 2 };
  state.filteredRows.sort((a, b) => {
    if (state.rowSort === "application") {
      return applicationNameForRow(a).localeCompare(applicationNameForRow(b), "ar")
        || String(a.domain).localeCompare(String(b.domain));
    }
    if (state.rowSort === "domain") {
      return String(a.domain).localeCompare(String(b.domain))
        || applicationNameForRow(a).localeCompare(applicationNameForRow(b), "ar");
    }
    if (state.rowSort === "classification") {
      return (riskOrder[classify(a).risk] ?? 3) - (riskOrder[classify(b).risk] ?? 3)
        || classify(a).label.localeCompare(classify(b).label, "ar")
        || (Date.parse(rowLastObservedAt(b)) || 0) - (Date.parse(rowLastObservedAt(a)) || 0);
    }
    return (Date.parse(rowLastObservedAt(b)) || 0) - (Date.parse(rowLastObservedAt(a)) || 0)
      || String(a.domain).localeCompare(String(b.domain));
  });
}

function renderRows() {
  const body = el("reportRows");
  body.replaceChildren();

  if (!state.filteredRows.length) {
    const row = document.createElement("tr");
    row.className = "empty-row";
    const cell = document.createElement("td");
    cell.colSpan = 4;
    const movedCount = state.reportRows.filter((item) =>
      operationIsVisible(operationKeyForRow(item))
    ).length;
    cell.textContent = state.reportRows.length
      ? movedCount
        ? "No items here; transferred hostnames appear under Privacy Protection Actions"
        : "No results match the filter"
      : "No report has been imported";
    row.appendChild(cell);
    body.appendChild(row);
  }

  for (const item of state.filteredRows) {
    const row = document.createElement("tr");
    const application = document.createElement("td");
    application.className = "application-cell";
    const identity = applicationIdentityForRow(item);
    if (identity.names.length > 1) {
      const sharedKey = normalizeDomain(item.domain);
      const expanded = state.expandedSharedDomains.has(sharedKey);
      const shared = document.createElement("div");
      shared.className = "shared-applications";
      const toggle = document.createElement("button");
      toggle.type = "button";
      toggle.className = "shared-applications-toggle";
      toggle.textContent = "+ Applications";
      toggle.title = "Show applications associated with this hostname";
      toggle.setAttribute("aria-expanded", expanded ? "true" : "false");
      const names = document.createElement("div");
      names.className = "shared-application-names";
      names.hidden = !expanded;
      for (const name of identity.names) {
        const itemName = document.createElement("span");
        itemName.textContent = name;
        names.appendChild(itemName);
      }
      toggle.addEventListener("click", () => {
        names.hidden = !names.hidden;
        if (names.hidden) state.expandedSharedDomains.delete(sharedKey);
        else state.expandedSharedDomains.add(sharedKey);
        toggle.setAttribute("aria-expanded", names.hidden ? "false" : "true");
      });
      shared.append(toggle, names);
      application.appendChild(shared);
    } else {
      const applicationName = document.createElement("strong");
      applicationName.textContent = identity.label;
      application.appendChild(applicationName);
    }
    const applicationSource = document.createElement("small");
    applicationSource.className = `application-attribution${identity.attributed ? " attributed" : ""}`;
    applicationSource.textContent = identity.source;
    application.title = `${identity.label} — ${identity.source}`;
    application.appendChild(applicationSource);
    const domain = document.createElement("td");
    domain.className = "domain-cell";
    domain.textContent = item.domain || "—";
    domain.dir = "ltr";
    domain.title = domain.textContent;
    const rating = classify(item);
    const category = document.createElement("td");
    category.className = "classification-cell";
    const tag = document.createElement("span");
    tag.className = `tag ${rating.key}`;
    tag.textContent = `${rating.label} • ${rating.stageLabel}`;
    tag.title = `${rating.note} — ${rating.confidenceLabel}`;
    const cleanDomain = normalizeDomain(item.domain);
    const itemOperationKey = operationKeyForRow(item);
    const manage = document.createElement("button");
    const managed = Boolean(state.policy.domains?.[cleanDomain]);
    const inOperations = operationIsVisible(itemOperationKey);
    manage.type = "button";
    manage.className = `manage-domain${managed ? " managed" : ""}${managed && !inOperations ? " detached" : ""}`;
    manage.textContent = inOperations
      ? "Already in actions"
      : managed ? "Transfer to actions • has a saved action" : "Transfer to actions";
    manage.title = inOperations
      ? "Hostname is already in Privacy Protection Actions"
      : managed
        ? "Transfer to actions without changing the saved policy"
        : "Transfer to actions only; no policy is created until you choose an action";
    manage.disabled = !cleanDomain.includes(".");
    manage.addEventListener("click", () => manageActivityItem(item));
    const source = document.createElement("small");
    source.className = "coverage-source";
    const observation = item.coverageState === "stored"
      ? "Saved from an earlier review"
      : `${Number(item.hits) || 1} recorded requests`;
    source.textContent = `${rowTypeLabel(item)} • ${observation} • ${rating.confidenceLabel}`;
    category.append(tag, manage, source);
    const time = document.createElement("td");
    time.className = "last-seen-cell";
    const observedAt = rowLastObservedAt(item);
    time.textContent = localDateTime(observedAt);
    time.title = observedAt || "No real saved observation time";
    row.append(application, domain, category, time);
    body.appendChild(row);
  }

  renderCoverageStrips();
}

async function loadReport(file) {
  const text = await file.text();
  const { rows, invalid } = parseNDJSON(text);
  const reportNetworkRows = rows
    .filter((row) => row.type === "networkActivity")
    .map((row) => ({ ...row, coverageState: "report" }));
  state.reportRows = groupReportRowsByDomain(reportNetworkRows);
  state.viewMode = "report";
  state.reportRows.sort(
    (a, b) => new Date(b.timeStamp).getTime() - new Date(a.timeStamp).getTime()
  );
  el("reportName").textContent = file.name;
  updateMetrics(rows);
  applyFilter();
  const discovered = new Map();
  const reportAttributions = new Map();
  for (const row of reportNetworkRows) {
    const bundleID = String(row.bundleID || "").trim();
    const domain = normalizeDomain(row.domain);
    if (!bundleID || !domain) continue;
    const key = bundleID.toLowerCase();
    if (!discovered.has(key)) {
      discovered.set(key, {
        bundleID,
        name: detectedName(bundleID, row),
        domains: new Set(),
      });
    }
    discovered.get(key).domains.add(domain);
    const attributionKey = `${key}|${domain}`;
    const currentAttribution = reportAttributions.get(attributionKey);
    if (!currentAttribution
      || (Date.parse(row.timeStamp) || 0) > (Date.parse(currentAttribution.observedAt) || 0)) {
      reportAttributions.set(attributionKey, {
        domain,
        bundleID,
        appName: detectedName(bundleID, row),
        processName: "",
        observedAt: row.timeStamp || new Date().toISOString(),
      });
    }
  }
  const discoveredPayload = [...discovered.values()].map((app) => ({
    bundleID: app.bundleID,
    name: app.name,
    domains: [...app.domains].sort(),
    lastSeen: state.reportRows[0]?.timeStamp || new Date().toISOString(),
  }));
  const batches = buildDiscoveredBatches(
    discoveredPayload,
    [...reportAttributions.values()]
  );
  for (const batch of batches) {
    const mergeResponse = await fetch("/api/apps/discovered", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(batch),
    });
    const mergeResult = await mergeResponse.json();
    if (!mergeResponse.ok) {
      throw new Error(mergeResult.error || "Unable to save detected applications");
    }
  }
  let linked = 0;
  for (const profile of state.profiles) {
    const detected = discovered.get(String(profile.bundleID || "").toLowerCase());
    if (!detected) continue;
    const response = await fetch(
      `/api/apps/${encodeURIComponent(profile.id)}/domains`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          source: "confirmed",
          domains: [...detected.domains],
        }),
      }
    );
    if (response.ok) linked += 1;
  }
  await refreshProfiles(el("appProfile").value);
  await refreshClassifications(false);
  if (discoveredPayload.length && !el("detectedAppsDialog").open) {
    el("detectedSearch").value = "";
    renderDetectedApps();
    el("detectedAppsDialog").showModal();
  }
  if (invalid) {
    toast(`Ignored ${invalid} invalid rows`, true);
  } else if (linked) {
    toast(`Analyzed and linked the report to ${linked} saved applications`);
  } else {
    toast(`Discovered ${discoveredPayload.length} applications from ${rows.length} records`);
  }
}

function groupReportRowsByDomain(rows) {
  const grouped = new Map();
  for (const row of rows) {
    const domain = normalizeDomain(row.domain);
    if (!domain) continue;
    const bundleID = String(row.bundleID || "").trim();
    const appName = bundleID ? detectedName(bundleID, row) : "";
    const existing = grouped.get(domain);
    if (!existing) {
      grouped.set(domain, {
        ...row,
        domain,
        hits: 1,
        applications: bundleID ? [{ bundleID, name: appName }] : [],
      });
      continue;
    }
    existing.hits += 1;
    if ((Date.parse(row.timeStamp) || 0) > (Date.parse(existing.timeStamp) || 0)) {
      existing.timeStamp = row.timeStamp;
      existing.domainType = row.domainType;
      existing.initiatedType = row.initiatedType;
    }
    if (bundleID && !existing.applications.some(
      (app) => String(app.bundleID).toLowerCase() === bundleID.toLowerCase()
    )) {
      existing.applications.push({ bundleID, name: appName });
    }
  }
  for (const row of grouped.values()) {
    if (row.applications.length === 1) {
      row.bundleID = row.applications[0].bundleID;
      row.context = row.applications[0].name;
    } else if (row.applications.length > 1) {
      row.bundleID = "Shared hostname";
      row.context = "";
    }
  }
  return [...grouped.values()];
}

const REPORT_IMPORT_REQUEST_LIMIT = 96 * 1024;
const REPORT_APP_DOMAIN_CHUNK = 100;

function jsonUTF8Size(value) {
  return new TextEncoder().encode(JSON.stringify(value)).length;
}

function buildSizedBatches(items, key) {
  const batches = [];
  let current = [];
  for (const item of items) {
    const candidate = [...current, item];
    const payload = {
      apps: key === "apps" ? candidate : [],
      attributions: key === "attributions" ? candidate : [],
    };
    if (current.length && jsonUTF8Size(payload) > REPORT_IMPORT_REQUEST_LIMIT) {
      batches.push({
        apps: key === "apps" ? current : [],
        attributions: key === "attributions" ? current : [],
      });
      current = [item];
    } else {
      current = candidate;
    }
  }
  if (current.length) {
    batches.push({
      apps: key === "apps" ? current : [],
      attributions: key === "attributions" ? current : [],
    });
  }
  return batches;
}

function buildDiscoveredBatches(apps, attributions) {
  const appParts = [];
  for (const app of apps) {
    const domains = Array.isArray(app.domains) ? app.domains : [];
    if (!domains.length) {
      appParts.push({ ...app, domains: [] });
      continue;
    }
    for (let index = 0; index < domains.length; index += REPORT_APP_DOMAIN_CHUNK) {
      appParts.push({
        ...app,
        domains: domains.slice(index, index + REPORT_APP_DOMAIN_CHUNK),
      });
    }
  }
  return [
    ...buildSizedBatches(appParts, "apps"),
    ...buildSizedBatches(attributions, "attributions"),
  ];
}

function actionLabel(action) {
  return {
    allow: "Allow",
    monitor: "Monitor",
    block: "Block",
  }[action] || action;
}

function operationEntries(profile = selectedAppProfile()) {
  const keys = new Set(state.operationTray.domains);
  if (profile) {
    for (const key of [...keys]) {
      if (!profileDomains(profile).has(key)) keys.delete(key);
    }
  }
  const saved = state.policy.domains || {};
  return [...keys]
    .map((key) => {
      const domain = normalizeDomain(key);
      if (!domain || !domain.includes(".")) return null;
      const rating = domainPrivacyProfile(domain);
      const settings = saved[domain];
      const stats = state.domainStats?.[domain] || {};
      const classification = state.classifications.domains?.[domain] || {};
      return {
        key: domain,
        kind: "domain",
        domain,
        displayName: settings?.label || domain,
        settings: settings || {
          action: "",
          label: domain,
          note: `${rating.note} — Transferred manually from application activity and awaiting your decision`,
        },
        rating,
        observedAt: stats.lastObservedAt || classification.lastObservedAt || classification.lastSeen || "",
        blockedAt: stats.lastBlockedAt || "",
        observedCount: Number(stats.observedCount) || 0,
        blockedCount: Number(stats.blockedCount) || 0,
        lastAction: stats.lastAction || "",
      };
    })
    .filter(Boolean)
    .sort((entryA, entryB) => {
      if (state.operationTray.sort === "blocked") {
        return (Date.parse(entryB.blockedAt) || 0) - (Date.parse(entryA.blockedAt) || 0)
          || (Date.parse(entryB.observedAt) || 0) - (Date.parse(entryA.observedAt) || 0);
      }
      if (state.operationTray.sort === "name") {
        return entryA.displayName.localeCompare(entryB.displayName, "ar");
      }
      if (state.operationTray.sort === "classification") {
        const riskOrder = { red: 0, orange: 1, green: 2 };
        return (riskOrder[entryA.rating.risk] ?? 3) - (riskOrder[entryB.rating.risk] ?? 3)
          || (Date.parse(entryB.observedAt) || 0) - (Date.parse(entryA.observedAt) || 0);
      }
      const byTime = (Date.parse(entryB.observedAt) || 0) - (Date.parse(entryA.observedAt) || 0);
      if (byTime) return byTime;
      const ratingA = entryA.rating;
      const ratingB = entryB.rating;
      const riskOrder = { red: 0, orange: 1, green: 2 };
      const byRisk = (riskOrder[ratingA.risk] ?? 3) - (riskOrder[ratingB.risk] ?? 3);
      if (byRisk) return byRisk;
      const actionOrder = { block: 0, monitor: 1, allow: 2 };
      const byAction = (actionOrder[entryA.settings.action] ?? 3) - (actionOrder[entryB.settings.action] ?? 3);
      return byAction || entryA.displayName.localeCompare(entryB.displayName, "ar");
    });
}

function saveOperationTray() {
  try {
    window.localStorage.setItem(
      operationTrayStorageKey,
      JSON.stringify([...state.operationTray.domains].sort())
    );
  } catch {
    // Keep the tray usable for the current session if browser storage is unavailable.
  }
}

function operationIsVisible(domain) {
  return state.operationTray.domains.has(operationKey(domain));
}

function addOperationToTray(domain) {
  const clean = operationKey(domain);
  if (!clean) return;
  state.operationTray.domains.add(clean);
  saveOperationTray();
}

function removeOperationFromTray(domain) {
  state.operationTray.domains.delete(operationKey(domain));
  saveOperationTray();
  renderPolicy();
  applyFilter();
  toast(`Removed ${domain} from actions; permanent observation evidence was preserved`);
}

function clearOperationsView() {
  state.operationTray.domains = new Set();
  state.operationTray.filter = "";
  el("operationFilter").value = "";
  saveOperationTray();
  renderPolicy();
  applyFilter();
  toast("The actions tray was cleared; permanent hostname activity was preserved");
}

function renderPolicy() {
  const list = el("policyList");
  list.replaceChildren();
  const profile = selectedAppProfile();
  const trayEntries = operationEntries(profile);
  const query = state.operationTray.filter.trim().toLowerCase();
  const entries = trayEntries.filter((entry) => {
    if (!query) return true;
    return [entry.key, entry.displayName, entry.settings.label, entry.settings.note,
      entry.rating.label, actionLabel(entry.settings.action)]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(query));
  });
  if (!entries.length) {
    list.classList.add("policy-list-empty");
    if (query && trayEntries.length) {
      list.textContent = "No action matches the filter.";
    } else list.textContent = "No actions yet. Transfer a hostname manually from Application Activity & Connections.";
  } else {
    list.classList.remove("policy-list-empty");
  }

  for (const entry of entries) {
    const { key, settings, rating } = entry;
    const domain = entry.domain || key;
    const item = document.createElement("div");
    item.className = "policy-item";
    const main = document.createElement("div");
    main.className = "policy-main";
    const identity = document.createElement("div");
    identity.className = "policy-domain";
    const label = document.createElement("strong");
    label.textContent = settings.label || entry.displayName;
    const classification = document.createElement("span");
    classification.className = `policy-classification ${rating.key}`;
    classification.textContent = `${rating.label} • ${rating.stageLabel}`;
    classification.title = `${rating.note} — ${rating.confidenceLabel}`;
    const code = document.createElement("code");
    code.textContent = domain;
    code.title = code.textContent;
    identity.append(label, code);

    const actions = document.createElement("div");
    actions.className = "policy-actions";
    for (const action of ["allow", "monitor", "block"]) {
      const button = document.createElement("button");
      button.type = "button";
      button.dataset.action = action;
      button.textContent = actionLabel(action);
      button.classList.toggle("active", settings.action === action);
      button.addEventListener("click", () => updatePolicy(domain, action));
      actions.appendChild(button);
    }
    const remove = document.createElement("button");
    remove.type = "button";
    remove.dataset.action = "remove";
    remove.className = "remove-operation";
    remove.textContent = "Remove from tray";
    remove.title = "Remove from the actions tray while preserving permanent observation evidence";
    remove.addEventListener("click", () => removeOperationFromTray(key));
    actions.appendChild(remove);
    if (!state.policy.domains?.[domain]) {
      const pending = document.createElement("span");
      pending.className = "decision-pending";
      pending.textContent = "Waiting for your decision";
      actions.appendChild(pending);
    }
    main.append(identity, actions);
    const meta = document.createElement("div");
    meta.className = "operation-meta-line";
    const observedText = entry.observedAt ? localDateTime(entry.observedAt) : "None";
    const blockedText = entry.blockedAt ? localDateTime(entry.blockedAt) : "None";
    const countText = `${entry.observedCount} observations — ${entry.blockedCount} blocks`;
    meta.textContent = [
      `${rating.label} — ${rating.confidenceLabel}`,
      `Latest observation ${observedText}`,
      `Latest block ${blockedText}`,
      countText,
    ].join(" • ");
    meta.title = `${rating.note} — ${meta.textContent}`;
    const operationApp = applicationIdentityForRow({ type: "networkActivity", domain });
    const appSummary = document.createElement("div");
    appSummary.className = "policy-app-summary";
    const appName = document.createElement("strong");
    appName.textContent = operationApp.label;
    appName.title = operationApp.names.join(", ") || operationApp.source;
    appSummary.append(classification, appName);
    const footer = document.createElement("div");
    footer.className = "operation-footer";
    footer.append(meta, appSummary);
    item.append(main, footer);
    list.appendChild(item);
  }
}

async function manageActivityItem(item) {
  const key = operationKeyForRow(item);
  if (!key || !key.includes(".")) return;
  if (operationIsVisible(key)) return;
  try {
    await linkDomainToSelectedProfile(key);
    addOperationToTray(key);
    renderPolicy();
    applyFilter();
    toast(`Transferred ${key} to actions without creating a policy; choose the action yourself`);
  } catch (error) {
    toast(error.message, true);
  }
}

async function linkDomainToSelectedProfile(domain) {
  const profile = selectedAppProfile();
  if (!profile) return;
  const response = await fetch(
    `/api/apps/${encodeURIComponent(profile.id)}/domains`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source: "observed", domains: [domain] }),
    }
  );
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Unable to link the hostname to the application");
  const index = state.profiles.findIndex((item) => item.id === profile.id);
  if (index >= 0) state.profiles[index] = result.profile;
}

async function updatePolicy(domain, action) {
  if (action === "block") {
    const accepted = window.confirm(
      `Only this exact hostname will be blocked:\n${domain}\n\nYou can reverse this immediately by choosing Allow. Continue?`
    );
    if (!accepted) return;
  }
  try {
    const response = await fetch("/api/policy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain, action }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Unable to update policy");
    state.policy.domains[domain] = {
      ...(state.policy.domains[domain] || { label: domain, note: "Added from activity" }),
      action,
    };
    renderPolicy();
    applyFilter();
    await refreshStatus();
    toast(`${domain}: ${actionLabel(action)}`);
  } catch (error) {
    toast(error.message, true);
  }
}

async function refreshPolicy() {
  const response = await fetch("/api/policy", { cache: "no-store" });
  if (!response.ok) throw new Error("Unable to load protection policy");
  state.policy = await response.json();
  renderPolicy();
}

async function refreshClassifications(render = true) {
  const response = await fetch("/api/classifications", { cache: "no-store" });
  if (!response.ok) throw new Error("Unable to load DNS Engine V3 classifications");
  const result = await response.json();
  state.classifications = {
    summary: result.summary || state.classifications.summary,
    domains: result.domains || {},
  };
  if (render) {
    if (state.viewMode === "live") renderLiveActivity();
    renderPolicy();
  }
  return result;
}

async function analyzeDomainsNow() {
  const button = el("analyzeDomains");
  button.disabled = true;
  button.textContent = "Studying...";
  try {
    const response = await fetch("/api/classifications/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Unable to start the V3 study");
    toast(`Started V3 study for ${Number(result.queued) || 0} hostnames; permanent classifications are preserved`);
    window.setTimeout(() => refreshClassifications().catch(() => {}), 1200);
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
    button.textContent = "Run V3 Study";
  }
}

async function refreshOperationsNow() {
  try {
    await Promise.all([refreshPolicy(), refreshClassifications(false)]);
    renderPolicy();
    toast("Privacy Protection Actions refreshed");
  } catch (error) {
    toast(error.message, true);
  }
}

async function refreshStatus() {
  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    if (!response.ok) throw new Error("The service is not ready");
    const status = await response.json();
    state.dnsEngine = status.dnsEngine || null;
    state.appAttribution = status.appAttribution || null;
    if (status.classificationEngine) {
      state.classifications.summary = status.classificationEngine;
    }
    el("serviceStatus").className = "service ready";
    el("serviceStatus").textContent = "Local service is running";
    el("blockedCount").textContent = String(status.blockedDomains);
    el("dnsPort").textContent = `DNS: ${status.dnsPort}`;
    el("dnsSelfTest").textContent = status.dnsEngine?.lastSelfTest?.state === "passed"
      ? "DNS Self-test ✓"
      : "DNS Self-test";
    renderCoverageStrips();
  } catch {
    el("serviceStatus").className = "service failed";
    el("serviceStatus").textContent = "Service is stopped";
  }
}

function renderLiveActivity() {
  if (state.viewMode !== "live" || state.session.active) return;
  const grouped = new Map();
  const selected = selectedAppProfile();
  for (const item of state.recentItems) {
    const domain = normalizeDomain(item.domain);
    if (!domain || !domain.includes(".")) continue;
    const current = grouped.get(domain);
    if (current) {
      current.hits += 1;
      continue;
    }
    const matchingProfiles = state.profiles.filter((profile) =>
      profileDomains(profile).has(domain)
    );
    const detectedMatches = detectedAppsForDomain(domain);
    const owner = selected && profileDomains(selected).has(domain)
      ? selected
      : matchingProfiles.length === 1 ? matchingProfiles[0] : null;
    const detectedOwner = !owner && detectedMatches.length === 1 ? detectedMatches[0] : null;
    const sharedNames = [...new Set([
      ...matchingProfiles.map((profile) => profile.name),
      ...detectedMatches.map((app) => app.name || app.bundleID),
    ])].join(", ");
    grouped.set(domain, {
      type: "networkActivity",
      bundleID: owner?.bundleID || detectedOwner?.bundleID || (sharedNames ? "Shared hostname" : `Device ${item.client || "iPhone"}`),
      profileID: owner?.id || "",
      context: owner?.name || detectedOwner?.name || sharedNames,
      domain,
      domainType: isTracker(domain) ? 1 : 2,
      initiatedType: "LiveDNS",
      timeStamp: item.time,
      hits: 1,
      action: item.action,
      coverageState: "live",
    });
  }

  for (const domain of knownDomainsForView(selected)) {
    if (grouped.has(domain)) continue;
    const matchingProfiles = state.profiles.filter((profile) =>
      profileDomains(profile).has(domain)
    );
    const detectedMatches = detectedAppsForDomain(domain);
    const owner = selected || (matchingProfiles.length === 1 ? matchingProfiles[0] : null);
    const detectedOwner = !owner && detectedMatches.length === 1 ? detectedMatches[0] : null;
    const sharedNames = [...new Set([
      ...matchingProfiles.map((profile) => profile.name),
      ...detectedMatches.map((app) => app.name || app.bundleID),
    ])].join(", ");
    grouped.set(domain, {
      type: "networkActivity",
      bundleID: owner?.bundleID || detectedOwner?.bundleID || (sharedNames ? "Shared hostname" : "Saved evidence"),
      profileID: owner?.id || "",
      context: owner?.name || detectedOwner?.name || sharedNames,
      domain,
      domainType: isTracker(domain) ? 1 : 2,
      initiatedType: "StoredCoverage",
      timeStamp: "",
      hits: 0,
      action: state.policy.domains?.[domain]?.action || "monitor",
      coverageState: "stored",
    });
  }
  state.reportRows = [...grouped.values()].sort(
    (a, b) => {
      const liveOrder = Number(b.coverageState === "live") - Number(a.coverageState === "live");
      if (liveOrder) return liveOrder;
      const timeOrder = (Date.parse(b.timeStamp) || 0) - (Date.parse(a.timeStamp) || 0);
      return timeOrder || String(a.domain).localeCompare(String(b.domain));
    }
  );
  state.reportRows.sort((a, b) => {
    const riskOrder = { red: 0, orange: 1, green: 2 };
    const byRisk = (riskOrder[classify(a).risk] ?? 3) - (riskOrder[classify(b).risk] ?? 3);
    return byRisk || (Date.parse(b.timeStamp) || 0) - (Date.parse(a.timeStamp) || 0);
  });
  const selectedCount = selected
    ? state.reportRows.filter((row) => rowBelongsToProfile(row, selected)).length
    : state.reportRows.length;
  el("reportName").textContent = state.reportRows.length
    ? selected
      ? `Activity for ${selected.name} — ${selectedCount} hostnames from current and saved evidence`
      : `All activity — ${state.recentItems.length} live requests, ${state.reportRows.length} visible hostnames`
    : "Waiting for the first live iPhone connection";
  updateMetrics(state.reportRows);
  applyFilter(false);
}

async function refreshLogs(force = false) {
  try {
    if (force) {
      state.liveCursor = 0;
      state.recentItems = [];
    }
    let collected = [];
    if (!state.liveCursor) {
      const response = await fetch("/api/logs?limit=2000", { cache: "no-store" });
      if (!response.ok) return;
      const data = await response.json();
      collected = Array.isArray(data.items) ? data.items : [];
      state.attributions = Array.isArray(data.attributions) ? data.attributions : [];
      if (data.domainStats) state.domainStats = data.domainStats;
      else mergeDomainStats(collected);
      state.liveCursor = Number(data.lastEventId) || 0;
    } else {
      let hasMore = true;
      while (hasMore) {
        const response = await fetch(
          `/api/logs?after=${state.liveCursor}&limit=1000`,
          { cache: "no-store" }
        );
        if (!response.ok) return;
        const data = await response.json();
        const items = Array.isArray(data.items) ? data.items : [];
        if (Array.isArray(data.attributions)) state.attributions = data.attributions;
        if (data.domainStats) state.domainStats = data.domainStats;
        else mergeDomainStats(items);
        if (items.length) {
          collected.push(...items);
          state.liveCursor = Math.max(
            state.liveCursor,
            ...items.map((item) => Number(item.id) || 0)
          );
        }
        hasMore = Boolean(data.hasMore) && items.length > 0;
      }
    }

    captureSessionItems(collected);
    if (collected.length) {
      const byId = new Map(
        [...state.recentItems, ...collected].map((item) => [Number(item.id), item])
      );
      state.recentItems = [...byId.values()]
        .sort((a, b) => Number(b.id) - Number(a.id))
        .slice(0, 200);
    }
    renderLiveActivity();
    if (collected.length) renderPolicy();
  } catch {
    // The status badge already communicates service availability.
  }
}

async function refreshActivityNow() {
  state.viewMode = "live";
  await refreshLogs(true);
  toast("Activity refreshed from local evidence");
}

async function clearActivity() {
  const accepted = window.confirm(
    "Only the current DNS request history will be cleared. Previously discovered hostnames remain visible. Continue?"
  );
  if (!accepted) return;
  try {
    const response = await fetch("/api/logs", { method: "DELETE" });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Unable to clear activity");
    state.viewMode = "live";
    state.liveCursor = Number(result.lastEventId) || 0;
    state.recentItems = [];
    state.domainStats = {};
    renderLiveActivity();
    await refreshStatus();
    toast(`Cleared ${Number(result.removed) || 0} events`);
  } catch (error) {
    toast(error.message, true);
  }
}

function exportRules() {
  const blocked = Object.entries(state.policy.domains || {})
    .filter(([, settings]) => settings.action === "block")
    .map(([domain]) => domain);
  const content = [
    "# Privacy Protector — exact block rules",
    "# No wildcard rules",
    ...blocked,
    "",
  ].join("\n");
  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "privacy-protector-exact-blocklist.txt";
  link.click();
  URL.revokeObjectURL(link.href);
}

const permissionKeys = ["location", "motion", "tracking"];
const permissionActivityLabels = {
  location: "Uses location",
  motion: "Accesses motion and sensors",
  tracking: "Checks tracking permission",
};

function currentPermissionProfile() {
  return state.profiles.find((item) => item.id === el("permissionApp").value);
}

function permissionControl(profile) {
  if (!profile?.bundleID) return null;
  return state.privacy.apps?.[profile.bundleID] || null;
}

function permissionObservedLabel(key, result, evaluation) {
  const stateName = result?.[key]?.state || "not_seen";
  const verdict = evaluation?.[key]?.verdict || "not_verified";
  if (verdict === "violation") return { text: "Privacy violation", className: "violation" };
  if (verdict === "allowed") return { text: "Allowed by your choice", className: "protected" };
  if (verdict === "protected") return { text: "Blocked by iOS", className: "protected" };
  if (stateName === "used" || stateName === "authorized") {
    return { text: "Use under monitoring", className: "observed" };
  }
  if (stateName === "denied" || stateName === "restricted") {
    return { text: "Denied by iOS", className: "protected" };
  }
  if (stateName === "requested") return { text: "Permission requested", className: "observed" };
  return { text: "Not observed", className: "unknown" };
}

function privacyFindingItem(key, result, evaluation) {
  const item = result?.[key] || {};
  const verdict = evaluation?.[key]?.verdict || "not_verified";
  const activity = evaluation?.[key]?.activity || permissionActivityLabels[key];
  if (verdict === "violation") {
    return { key, verdict, tone: "violation", text: `${activity} — violation of your choice` };
  }
  if (verdict === "allowed") {
    return { key, verdict, tone: "allowed", text: `${activity} — Allowed by your choice` };
  }
  if (verdict === "protected") {
    const action = key === "tracking" && item.checks
      ? "Tracking-permission check"
      : `Attempted ${activity}`;
    return { key, verdict, tone: "protected", text: `${action} — Blocked by iOS` };
  }
  if (verdict === "observed") {
    return { key, verdict, tone: "observed", text: `${activity} — under monitoring` };
  }
  return null;
}

function renderPrivacyFinding(profile, result, evaluation) {
  const finding = el("privacyFinding");
  const title = el("privacyFindingTitle");
  const description = el("privacyFindingText");
  const tags = el("privacyFindingTags");
  const items = permissionKeys
    .map((key) => privacyFindingItem(key, result, evaluation))
    .filter(Boolean);
  const violations = items.filter((item) => item.verdict === "violation");
  const appIncidents = (state.privacy.incidents || [])
    .filter((item) => item.bundleID === profile?.bundleID);
  tags.replaceChildren();

  for (const item of items) {
    const tag = document.createElement("span");
    tag.className = `privacy-finding-tag ${item.tone}`;
    tag.textContent = item.text;
    tags.appendChild(tag);
  }

  el("privacyIncidentCount").textContent = appIncidents.length
    ? `${appIncidents.length} saved incidents — latest ${localTime(appIncidents[0].capturedAt)}`
    : "No saved incidents";
  el("privacySeverity").textContent = violations.length ? "High" : "No confirmed violation";
  const containment = result?.containment || {};
  el("privacyProtectionAction").textContent = items.some((item) => item.verdict === "protected")
      ? "iOS blocked actual access"
      : violations.length ? "Waiting for your manual decision" : "Continuous monitoring";

  if (!profile || !result?.capturedAt) {
    finding.className = "privacy-finding neutral";
    title.textContent = "No classification yet";
    description.textContent = "Run a verification session to distinguish permitted use from a privacy-choice violation.";
    return;
  }
  if (violations.length) {
    finding.className = "privacy-finding violation";
    title.textContent = "Privacy-choice violation";
    description.textContent = `${profile.name} received data from a category you chose to deny; review related hostnames and choose a manual action.`;
    return;
  }
  if (items.some((item) => item.verdict === "allowed")) {
    finding.className = "privacy-finding allowed";
    title.textContent = "Observed use matches your choice";
    description.textContent = "No confirmed violation in this session; permitted and iOS-blocked activity is shown below.";
    return;
  }
  if (items.length) {
    finding.className = "privacy-finding protected";
    title.textContent = "The application did not receive denied data";
    description.textContent = "A permission check was observed, but iOS blocked actual access according to the evidence.";
    return;
  }
  finding.className = "privacy-finding neutral";
  title.textContent = "No classified data use observed";
  description.textContent = "This session contains no evidence of location, motion, or tracking use.";
}

function exportPrivacyIncidents() {
  const profile = currentPermissionProfile();
  const incidents = (state.privacy.incidents || [])
    .filter((item) => !profile?.bundleID || item.bundleID === profile.bundleID);
  const blob = new Blob(
    [JSON.stringify({ exportedAt: new Date().toISOString(), incidents }, null, 2)],
    { type: "application/json;charset=utf-8" }
  );
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `privacy-incidents-${profile?.bundleID || "all"}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
}

function permissionEvidence(key, result) {
  const item = result?.[key] || {};
  if (key === "location") {
    if (item.updates) return `${item.updates} location updates reached the application`;
    if (item.requests) return `${item.requests} location requests without a visible update`;
    return "No location request or update was observed in the latest session.";
  }
  if (key === "motion") {
    if (item.samples) return `${item.samples} motion samples reached the application`;
    if (item.sessions) return `${item.sessions} sensor sessions started without visible samples`;
    return "No motion samples appeared in the latest session.";
  }
  const trackingLabels = {
    0: "Permission not determined",
    1: "Tracking restricted by the system",
    2: "Tracking permission denied",
    3: "Tracking permission allowed",
  };
  if (item.authorizationStatus in trackingLabels) {
    return `${trackingLabels[item.authorizationStatus]} — ${item.checks || 0} checks`;
  }
  return item.checks
    ? `Tracking status was queried ${item.checks} times`
    : "No tracking query appeared in the latest session.";
}

function renderPermissionInstructions(profile) {
  const denied = permissionKeys.filter((key) => state.privacy.desired[key] === "deny");
  if (!profile) {
    el("permissionInstruction").textContent =
      "Add an application with its Bundle ID to monitoring first.";
    return;
  }
  if (!denied.length) {
    el("permissionInstruction").textContent =
      "Choose Deny on a card to show the relevant iPhone setting.";
    return;
  }
  const paths = {
    location: `Location: Settings > Privacy & Security > Location Services > ${profile.name} ← Never`,
    motion: `Motion: Settings > Privacy & Security > Motion & Fitness > disable ${profile.name}`,
    tracking: `Tracking: Settings > Privacy & Security > Tracking > disable ${profile.name}`,
  };
  el("permissionInstruction").textContent = denied.map((key) => paths[key]).join("  |  ");
}

function renderPermissionCapture() {
  const capture = state.privacy.capture || { active: false };
  const active = Boolean(capture.active);
  el("startPermissionCapture").disabled = active || !currentPermissionProfile();
  el("stopPermissionCapture").disabled = !active;
  el("permissionApp").disabled = active;
  if (active) {
    el("permissionCaptureTitle").textContent = `Verification in progress: ${capture.appName || "Application"}`;
    el("permissionCaptureStatus").textContent =
      "Use the application normally on the iPhone, then select Stop and Analyze.";
  } else {
    el("permissionCaptureTitle").textContent = "Live verification is stopped";
    el("permissionCaptureStatus").textContent =
      "Start verification, use the application on the iPhone, then stop to analyze location, motion, and tracking evidence.";
  }
}

function renderPermissionCenter(loadStored = false) {
  const profile = currentPermissionProfile();
  const control = permissionControl(profile);
  if (loadStored) {
    const defaults = state.privacy.defaults || {};
    state.privacy.desired = {
      location: control?.desired?.location || defaults.location || "deny",
      motion: control?.desired?.motion || defaults.motion || "deny",
      tracking: control?.desired?.tracking || defaults.tracking || "deny",
      systemState: control?.desired?.systemState || defaults.systemState || "monitor",
      containment: "monitor",
    };
  }
  el("permissionBundle").textContent = profile?.bundleID || "None Bundle ID";
  el("permissionProcess").textContent =
    `Process name: ${profile?.processName || "Unknown - reconnect the iPhone over USB"}`;

  const result = control?.lastResult || {};
  const evaluation = control?.evaluation || {};
  for (const key of permissionKeys) {
    const card = document.querySelector(`.permission-card[data-permission="${key}"]`);
    card.querySelectorAll(".permission-choice button").forEach((button) => {
      button.classList.toggle("active", button.dataset.value === state.privacy.desired[key]);
      button.disabled = !profile?.bundleID;
    });
    const status = permissionObservedLabel(key, result, evaluation);
    const statusNode = el(`${key}Observed`);
    statusNode.textContent = status.text;
    statusNode.className = `permission-status ${status.className}`;
    el(`${key}Evidence`).textContent = permissionEvidence(key, result);
  }
  renderPrivacyFinding(profile, result, evaluation);
  document.querySelectorAll(".system-protection-choice button").forEach((button) => {
    button.classList.toggle(
      "active",
      button.dataset.value === state.privacy.desired.systemState
    );
    button.disabled = !profile?.bundleID;
  });
  const protectionActive = state.privacy.desired.systemState === "block";
  const protectionStatus = el("systemProtectionStatus");
  protectionStatus.textContent = protectionActive ? "Block transmission active" : "Monitor only";
  protectionStatus.className =
    `permission-status ${protectionActive ? "violation" : "observed"}`;
  el("systemProtectionEvidence").textContent =
    "Permission defaults are active; hostname evidence stays advisory until you apply a manual action.";
  const containment = result.containment || {};
  const containmentStatus = el("containmentStatus");
  containmentStatus.textContent = "Manual decision";
  containmentStatus.className = "permission-status observed";
  el("containmentEvidence").textContent = (containment.recommendedDomains || []).length
    ? `A violation is associated with ${(containment.recommendedDomains || []).length} hostnames; review them in activity and transfer only your selection manually.`
    : "No automatic transfer or blocking; review the classification and choose the action yourself.";
  renderPermissionInstructions(profile);
  renderPermissionCapture();

  const systemProtection = result.systemProtection || {};
  const checks = result.developerChecks || {};
  if (result.capturedAt) {
    const protectionText = systemProtection.detected
      ? `A system-protection signal appeared; ${systemProtection.requests || 0} requests and ${systemProtection.bytesSent || 0} bytes`
      : "No system-protection signal appeared";
    const checkText = checks.detected
      ? `Environment checks: ${(checks.signals || []).join(", ")}`
      : "No environment check appeared in the captured evidence";
    el("permissionSdkSummary").textContent =
      `${protectionText} — ${checkText} — Latest verification ${localTime(result.capturedAt)}`;
  } else {
    el("permissionSdkSummary").textContent =
      "No verification session has been recorded for these permissions.";
  }
}

function renderPermissionProfiles(preferredId = "") {
  const select = el("permissionApp");
  const selected = preferredId || select.value || el("appProfile").value;
  select.replaceChildren();
  const profiles = state.profiles.filter((profile) => profile.bundleID);
  for (const profile of profiles) {
    const option = document.createElement("option");
    option.value = profile.id;
    option.textContent = profile.name;
    select.appendChild(option);
  }
  if (profiles.some((profile) => profile.id === selected)) select.value = selected;
  if (!profiles.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "Add an application with a Bundle ID first";
    select.appendChild(option);
  }
  renderPermissionCenter(true);
}

async function refreshPrivacyControls(preferredId = "") {
  const response = await fetch("/api/privacy-controls", { cache: "no-store" });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Unable to load the Permission Center");
  state.privacy.apps = result.apps || {};
  state.privacy.defaults = result.defaults || state.privacy.defaults;
  state.privacy.capture = result.capture || { active: false };
  state.privacy.incidents = result.incidents || [];
  const balanced = state.policy.balancedProtection || {};
  el("globalProtectionStatus").textContent = balanced.enabled
    ? "Exact-domain baseline active"
    : "Permission defaults active";
  el("globalProtectionRules").textContent = String(balanced.exactRules || 0);
  renderPermissionProfiles(preferredId);
  renderCoverageStrips();
  renderPolicy();
}

async function savePermissionPolicy(showToast = true) {
  const profile = currentPermissionProfile();
  if (!profile?.bundleID) throw new Error("Choose an application with a Bundle ID");
  const response = await fetch("/api/privacy-controls", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      bundleID: profile.bundleID,
      appName: profile.name,
      desired: state.privacy.desired,
    }),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Unable to save permission choices");
  state.privacy.apps[profile.bundleID] = result.control;
  for (const rule of result.rules || []) {
    state.policy.domains[rule.domain] = rule.entry;
  }
  renderPolicy();
  applyFilter();
  await refreshStatus();
  renderPermissionCenter(true);
  if (showToast) toast(`Saved choices for ${profile.name}`);
}

async function startPermissionCapture() {
  const profile = currentPermissionProfile();
  if (!profile) return;
  try {
    await savePermissionPolicy(false);
    const response = await fetch("/api/privacy-capture/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ profileID: profile.id }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Unable to start verification");
    state.privacy.capture = result.capture;
    renderPermissionCapture();
    toast(`Started live verification for ${profile.name}`);
  } catch (error) {
    toast(error.message, true);
  }
}

async function stopPermissionCapture() {
  try {
    const response = await fetch("/api/privacy-capture/stop", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Unable to stop verification");
    state.privacy.capture = { active: false };
    state.privacy.apps[result.control.bundleID] = result.control;
    await refreshPolicy();
    await refreshPrivacyControls(currentPermissionProfile()?.id || "");
    toast("Permission analysis completed and was saved; hostname actions remain manual");
  } catch (error) {
    toast(error.message, true);
  }
}

async function openPermissionCenter() {
  try {
    await refreshProfiles(el("appProfile").value);
    await refreshPrivacyControls(el("appProfile").value);
    el("permissionDialog").showModal();
  } catch (error) {
    toast(error.message, true);
  }
}

function setDeveloperModeState(kind, title, detail) {
  const box = el("developerModeState");
  box.className = `developer-mode-state ${kind}`;
  box.setAttribute("aria-busy", kind === "checking" ? "true" : "false");
  el("developerModeStatus").textContent = title;
  el("developerModeDetail").textContent = detail;
  el("openDeveloperShield").classList.toggle("verified", kind === "protected");
}

async function refreshDeveloperModeStatus() {
  const button = el("refreshDeveloperMode");
  button.disabled = true;
  setDeveloperModeState(
    "checking",
    "Checking the iPhone...",
    "Reading the Developer Mode state reported by iOS."
  );
  try {
    const response = await fetch("/api/developer-mode/status", { cache: "no-store" });
    const result = await response.json();
    if (!response.ok || !result.ok) {
      throw new Error(result.error || "Unable to read Developer Mode status");
    }
    if (result.enabled) {
      setDeveloperModeState(
        "visible",
        "Developer Mode is visible to applications",
        "Disable it using the path below, then check again until it is reported as disabled."
      );
    } else {
      const version = result.productVersion ? ` — iOS ${result.productVersion}` : "";
      setDeveloperModeState(
        "protected",
        "Developer Mode is disabled",
        `Developer Mode is disabled on iPhone${version}. No further action is required.`
      );
    }
  } catch (error) {
    setDeveloperModeState(
      "unavailable",
      "Unable to verify the iPhone",
      `${String(error.message).replace(/[.!?]+$/, "")}. Confirm the iPhone is unlocked, paired, and reachable, then try again.`
    );
  } finally {
    button.disabled = false;
  }
}

function openDeveloperShield() {
  el("developerShieldDialog").showModal();
  refreshDeveloperModeStatus();
}

el("reportFile").addEventListener("change", (event) => {
  const [file] = event.target.files;
  if (file) loadReport(file).catch((error) => toast(error.message, true));
});
el("rowFilter").addEventListener("change", applyFilter);
el("rowSort").addEventListener("change", (event) => {
  state.rowSort = event.target.value;
  applyFilter();
});
el("showLive").addEventListener("click", () => {
  state.viewMode = "live";
  renderLiveActivity();
});
el("refreshActivity").addEventListener("click", () => {
  refreshActivityNow().catch((error) => toast(error.message, true));
});
el("dnsSelfTest").addEventListener("click", runDNSSelfTest);
el("analyzeDomains").addEventListener("click", analyzeDomainsNow);
el("clearActivity").addEventListener("click", clearActivity);
el("exportRules").addEventListener("click", exportRules);
el("refreshOperations").addEventListener("click", refreshOperationsNow);
el("clearOperationsView").addEventListener("click", clearOperationsView);
el("operationFilter").addEventListener("input", (event) => {
  state.operationTray.filter = event.target.value;
  renderPolicy();
});
el("operationSort").addEventListener("change", (event) => {
  state.operationTray.sort = event.target.value;
  renderPolicy();
});
el("appProfile").addEventListener("change", () => {
  updateSelectedAppControls();
  if (state.viewMode === "live") renderLiveActivity();
  else applyFilter();
  renderPolicy();
});
el("appForm").addEventListener("submit", saveAppProfile);
el("closeAppDialog").addEventListener("click", () => el("appDialog").close());
el("cancelApp").addEventListener("click", () => el("appDialog").close());
el("appDialog").addEventListener("click", (event) => {
  if (event.target === el("appDialog")) el("appDialog").close();
});
el("showDetectedApps").addEventListener("click", () => {
  el("detectedSearch").value = "";
  renderDetectedApps();
  el("detectedAppsDialog").showModal();
});
el("closeDetectedApps").addEventListener("click", () =>
  el("detectedAppsDialog").close()
);
el("detectedSearch").addEventListener("input", renderDetectedApps);
el("scanIPhoneApps").addEventListener("click", scanIPhoneApps);
el("detectedAppsDialog").addEventListener("click", (event) => {
  if (event.target === el("detectedAppsDialog")) {
    el("detectedAppsDialog").close();
  }
});
el("appBundleID").addEventListener("change", () => {
  const bundleID = el("appBundleID").value.trim().toLowerCase();
  const detected = state.detectedApps.find(
    (app) => String(app.bundleID || "").toLowerCase() === bundleID
  );
  if (detected?.processName && !el("appProcessName").value.trim()) {
    el("appProcessName").value = detected.processName;
  }
});
el("openPermissionCenter").addEventListener("click", openPermissionCenter);
el("openDeveloperShield").addEventListener("click", openDeveloperShield);
el("refreshDeveloperMode").addEventListener("click", refreshDeveloperModeStatus);
el("closeDeveloperShield").addEventListener("click", () =>
  el("developerShieldDialog").close()
);
el("dismissDeveloperShield").addEventListener("click", () =>
  el("developerShieldDialog").close()
);
el("developerShieldDialog").addEventListener("click", (event) => {
  if (event.target === el("developerShieldDialog")) {
    el("developerShieldDialog").close();
  }
});
el("closePermissionDialog").addEventListener("click", () =>
  el("permissionDialog").close()
);
el("permissionDialog").addEventListener("click", (event) => {
  if (event.target === el("permissionDialog") && !state.privacy.capture.active) {
    el("permissionDialog").close();
  }
});
el("permissionApp").addEventListener("change", () => renderPermissionCenter(true));
document.querySelectorAll(".permission-card").forEach((card) => {
  card.querySelectorAll(".permission-choice button").forEach((button) => {
    button.addEventListener("click", () => {
      state.privacy.desired[card.dataset.permission] = button.dataset.value;
      renderPermissionCenter(false);
    });
  });
});
document.querySelectorAll(".system-protection-choice button").forEach((button) => {
  button.addEventListener("click", () => {
    state.privacy.desired.systemState = button.dataset.value;
    renderPermissionCenter(false);
  });
});
el("exportPrivacyIncidents").addEventListener("click", exportPrivacyIncidents);
el("savePermissionPolicy").addEventListener("click", () => {
  savePermissionPolicy().catch((error) => toast(error.message, true));
});
el("startPermissionCapture").addEventListener("click", startPermissionCapture);
el("stopPermissionCapture").addEventListener("click", stopPermissionCapture);

function updateClock() {
  el("footerClock").textContent = new Intl.DateTimeFormat("en-GB", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date());
}

Promise.all([refreshPolicy(), refreshStatus(), refreshProfiles(), refreshClassifications(false)])
  .then(() => refreshPrivacyControls())
  .catch((error) => toast(error.message, true))
  .finally(() => refreshLogs());
updateClock();
setInterval(refreshLogs, 3000);
setInterval(() => refreshClassifications().catch(() => {}), 9000);
setInterval(refreshStatus, 12000);
setInterval(updateClock, 30000);
