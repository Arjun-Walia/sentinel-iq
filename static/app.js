const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const esc = (value) =>
  String(value ?? "—").replace(
    /[&<>"']/g,
    (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char],
  );
const fmt = (value) => Number(value || 0).toLocaleString("en-US");
const compact = (value) =>
  Number(value || 0) >= 1000 ? (value / 1000).toFixed(1) + "k" : fmt(Math.round(value));
const colors = {
  Critical: "#f49482",
  High: "#e4bd77",
  Medium: "#d5f478",
  Low: "#677b4c",
  Unknown: "#849079",
};
const sourceNames = { iam: "Identity & access", firewall: "Firewall", endpoint: "Endpoint" };
const paths = {
  overview: "M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z",
  activity: "M2 12h4l3-8 5 16 3-8h5",
  network: "M12 8v5M6 17l6-4 6 4 M9 2h6v6H9z M2 17h7v5H2z M15 17h7v5h-7z",
  sparkles: "m12 3 2.5 6.5L21 12l-6.5 2.5L12 21l-2.5-6.5L3 12l6.5-2.5L12 3Z M20 2v4M18 4h4",
  layers: "m12 3 10 5-10 5L2 8l10-5Z M2 12l10 5 10-5M2 16l10 5 10-5",
  bookmark: "M6 3h12v18l-6-4-6 4V3Z",
  shield: "m12 3 9 4v5c0 5-9 10-9 10S3 17 3 12V7l9-4Z M8 12l3 3 5-6",
  search: "M21 21l-5-5 M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0",
  settings:
    "m10 2 4 0 1 3 3 1 3 3-2 3 1 3-3 3-3-1-2 3-4-1-1-3-3-1-1-4 3-2 0-3 3-1 1-3Z M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0",
  "arrow-up-right": "M6 18 18 6M6 6h12v12",
  "arrow-right": "M4 12h16m-6-6 6 6-6 6",
  "arrow-up": "M12 20V4m-6 6 6-6 6 6",
  calendar: "M4 5h16v16H4z M8 2v6m8-6v6M4 10h16",
  users:
    "M16 21v-3a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v3M12 6a4 4 0 1 1-8 0 4 4 0 0 1 8 0M17 3a4 4 0 0 1 0 8M22 21v-3a4 4 0 0 0-3-4",
  download: "M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5",
  x: "m6 6 12 12M6 18 18 6",
  crosshair: "M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0M12 2v5m0 10v5M2 12h5m10 0h5",
  info: "M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0M12 11v6m0-10v.1",
  database: "M21 5c0 2-4 3-9 3S3 7 3 5s4-3 9-3 9 1 9 3ZM3 5v14c0 4 18 4 18 0V5M3 12c0 4 18 4 18 0",
  chart: "M3 3v18h18M7 16v-5m5 5V7m5 9V4",
  code: "m8 6-6 6 6 6m8-12 6 6-6 6m-3-14-2 16",
  monitor: "M3 3h18v13H3z M12 16v5m-5 0h10",
  alert: "m12 3 10 18H2L12 3Zm0 6v5m0 3v.1",
  check: "m5 12 4 4L19 6",
  globe: "M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0M3 12h18M12 3c5 5 5 13 0 18-5-5-5-13 0-18",
  clock: "M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0M12 7v5l3 2",
};
const icon = (name) =>
  `<i aria-hidden="true"><svg viewBox="0 0 24 24"><path d="${paths[name] || paths.shield}"/></svg></i>`;
function icons(root = document) {
  $$("[data-icon]", root).forEach((el) => {
    el.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="${paths[el.dataset.icon] || paths.shield}"/></svg>`;
  });
}
const state = {
  view: "overview",
  data: null,
  meta: null,
  page: 1,
  pages: 1,
  host: null,
  hostArgs: null,
  hostData: null,
  sequence: 0,
  eventSequence: 0,
};
const views = {
  overview: [
    "Overview",
    "See the signals. <span>Connect the dots.</span>",
    "Turn fragmented telemetry into a clearer picture of your security landscape.",
    "YOUR SECURITY POSTURE, AT A GLANCE",
  ],
  events: [
    "Event explorer",
    "Every event. <span>Every detail.</span>",
    "Search and inspect the cleaned evidence behind every signal.",
    "FROM TELEMETRY TO EVIDENCE",
  ],
  graph: [
    "Threat connections",
    "Isolated alerts. <span>Connected context.</span>",
    "Follow shared hosts across your identity, network, and endpoint telemetry.",
    "FOLLOW THE EVIDENCE",
  ],
  assistant: [
    "Ask Sentinel",
    "A better question. <span>A clearer picture.</span>",
    "Explore your security data through grounded answers and generated charts.",
    "INTELLIGENCE, ON DEMAND",
  ],
  quality: [
    "Data quality",
    "Messy inputs. <span>Trusted foundations.</span>",
    "Trace what changed, what was removed, and what still needs attention.",
    "A PIPELINE YOU CAN INSPECT",
  ],
  cases: [
    "Investigations",
    "Keep the context. <span>Move the work forward.</span>",
    "A shared queue for the hosts and evidence that deserve your attention.",
    "YOUR ANALYST WORKSPACE",
  ],
};
function filters() {
  return { period: $("#period").value, source: $("#source").value, department: $("#department").value };
}
function eventFilters() {
  return { ...filters(), severity: $("#severity-filter").value, q: $("#event-search").value.trim() };
}
function params(args) {
  return new URLSearchParams(args).toString();
}
async function api(url, options = {}) {
  const response = await fetch(url, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status}).`);
  return data;
}
function post(url, body) {
  return api(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}
function toast(message) {
  $("#toast").textContent = message;
  $("#toast").classList.remove("hidden");
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => $("#toast").classList.add("hidden"), 4000);
}
function error(message) {
  $("#error-banner").textContent = message;
  $("#error-banner").classList.toggle("hidden", !message);
}
function dateTime(value) {
  return value
    ? new Date(value.replace(" ", "T") + (/[Z+]$/.test(value) ? "" : "Z")).toLocaleString("en-GB", {
        day: "2-digit",
        month: "short",
        hour: "2-digit",
        minute: "2-digit",
        timeZone: "UTC",
      })
    : "Unresolved timestamp";
}
function shortDate(value) {
  return new Date(value + "T00:00:00Z").toLocaleDateString("en-GB", {
    day: "2-digit",
    month: "short",
    timeZone: "UTC",
  });
}
function severity(value) {
  return `<span class="severity-badge ${esc(value)}"><span class="dot"></span>${esc(value)}</span>`;
}
function empty(message, title = "No matching evidence") {
  return `<div class="empty">${icon("search")}<h3>${esc(title)}</h3>${esc(message)}</div>`;
}
function lineChart(rows, valueKey = "total", secondary = "high_risk") {
  if (!rows.length) return '<div class="chart-empty">No dated events in this scope.</div>';
  const width = 700,
    height = 190,
    left = 39,
    right = 15,
    top = 14,
    bottom = 30;
  const plotW = width - left - right,
    plotH = height - top - bottom;
  const max = Math.max(1, ...rows.map((r) => Number(r[valueKey]))) * 1.15;
  const x = (i) => left + (rows.length === 1 ? plotW / 2 : (i * plotW) / (rows.length - 1));
  const y = (v) => top + plotH - ((Number(v) || 0) * plotH) / max;
  const points = (key) => rows.map((r, i) => `${x(i)},${y(r[key])}`).join(" ");
  const id = "fill-" + Math.random().toString(36).slice(2);
  let grid = "";
  for (let i = 0; i < 4; i++) {
    const value = (max * i) / 3;
    grid += `<line class="chart-grid" x1="${left}" y1="${y(value)}" x2="${width - right}" y2="${y(value)}"/><text class="chart-label" x="${left - 9}" y="${y(value) + 3}" text-anchor="end">${compact(value)}</text>`;
  }
  const labelIndexes = [
    ...new Set(
      Array.from({ length: Math.min(6, rows.length) }, (_, i) =>
        Math.round((i * (rows.length - 1)) / Math.max(1, Math.min(6, rows.length) - 1)),
      ),
    ),
  ];
  const labels = labelIndexes
    .map(
      (i) =>
        `<text class="chart-label" x="${x(i)}" y="${height - 7}" text-anchor="${i === 0 ? "start" : i === rows.length - 1 ? "end" : "middle"}">${esc(shortDate(rows[i].day || rows[i].label))}</text>`,
    )
    .join("");
  const base = top + plotH;
  const areaKey = secondary || valueKey;
  return `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="${secondary ? "Event volume and high-risk" : "Event count"} over time"><defs><linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1"><stop stop-color="#cce977" stop-opacity=".23"/><stop offset="1" stop-color="#cce977" stop-opacity="0"/></linearGradient></defs>${grid}<path d="M${x(0)},${base} L${points(areaKey)} L${x(rows.length - 1)},${base} Z" fill="url(#${id})"/><polyline points="${points(valueKey)}" fill="none" stroke="${secondary ? "#65784b" : "#d5f478"}" stroke-width="2" stroke-linejoin="round"/>${secondary ? `<polyline points="${points(secondary)}" fill="none" stroke="#d5f478" stroke-width="2.5" stroke-linejoin="round"/>` : ""}${rows.map((r, i) => `<circle cx="${x(i)}" cy="${y(r[areaKey])}" r="${rows.length < 10 ? 3 : 1.8}" fill="#d5f478"/><rect class="chart-hover" x="${x(i) - Math.max(5, plotW / rows.length / 2)}" y="${top}" width="${Math.max(10, plotW / rows.length)}" height="${plotH}" tabindex="0"><title>${esc(r.day || r.label)}: ${fmt(r[valueKey])} ${secondary ? `events; ${fmt(r[secondary])} high risk` : "events"}</title></rect>`).join("")}${labels}</svg>`;
}
function sparkline(rows) {
  if (rows.length < 2) return "";
  const values = rows.map((r) => r.high_risk),
    max = Math.max(...values),
    min = Math.min(...values);
  return `<svg class="metric-spark" viewBox="0 0 70 30" aria-hidden="true"><polyline points="${values.map((v, i) => `${(i * 70) / (values.length - 1)},${27 - ((v - min) / Math.max(1, max - min)) * 23}`).join(" ")}" fill="none" stroke="#cce97a" stroke-width="1.5"/></svg>`;
}
function bars(rows, clickable = false) {
  if (!rows.length) return '<div class="chart-empty">No matching events.</div>';
  const max = Math.max(1, ...rows.map((r) => r.value));
  return rows
    .map(
      (r) =>
        `<${clickable ? "button" : "div"} class="bar-row" ${clickable ? `data-department="${esc(r.label)}" title="Filter to ${esc(r.label)}"` : ""}><span class="bar-label" title="${esc(r.label)}">${esc(r.label)}</span><span class="bar-track"><span class="bar-fill" style="width:${Math.max(0, (r.value / max) * 100)}%"></span></span><span class="bar-number">${fmt(r.value)}</span></${clickable ? "button" : "div"}>`,
    )
    .join("");
}
function drawDonut(rows) {
  const total = rows.reduce((sum, r) => sum + r.value, 0),
    radius = 45,
    circ = 2 * Math.PI * radius;
  let offset = 0;
  const segments = rows
    .map((r) => {
      const length = total ? (r.value / total) * circ : 0;
      const segment = `<circle cx="65" cy="65" r="${radius}" fill="none" stroke="${colors[r.label] || colors.Unknown}" stroke-width="10" stroke-dasharray="${Math.max(0, length - 3)} ${circ - Math.max(0, length - 3)}" stroke-dashoffset="${-offset}" transform="rotate(-90 65 65)"><title>${esc(r.label)}: ${fmt(r.value)}</title></circle>`;
      offset += length;
      return segment;
    })
    .join("");
  $("#severity-donut").innerHTML =
    `<svg viewBox="0 0 130 130" role="img" aria-label="Risk distribution of ${fmt(total)} events"><circle cx="65" cy="65" r="45" fill="none" stroke="#303c24" stroke-width="10"/>${segments}<text x="65" y="64" text-anchor="middle" fill="#e3ebd5" font-size="23" font-family="Manrope, sans-serif">${compact(total)}</text><text x="65" y="81" text-anchor="middle" fill="#8b9b77" font-size="8" font-family="Manrope, sans-serif">total signals</text></svg>`;
  $("#severity-legend").innerHTML = rows
    .map(
      (r) =>
        `<div class="severity-row"><span class="dot" style="background:${colors[r.label] || colors.Unknown}"></span>${esc(r.label)}<strong>${fmt(r.value)}</strong></div>`,
    )
    .join("");
}
function renderOverview(data) {
  const m = data.metrics;
  const metrics = [
    ["Total events", m.total, "activity", `${fmt(m.identities)} associated identities`, false],
    [
      "High-risk signals",
      m.high_risk,
      "shield",
      `${m.total ? ((m.high_risk / m.total) * 100).toFixed(1) : 0}% of selected events`,
      true,
    ],
    ["Observed hosts", m.hosts, "monitor", "Across selected telemetry sources", false],
    ["Open endpoint alerts", m.open_alerts, "alert", "Open + investigating statuses", false],
  ];
  $("#metrics").innerHTML = metrics
    .map(
      ([title, value, ico, foot, emphasis]) =>
        `<article class="card metric ${emphasis ? "emphasis" : ""}"><div class="metric-head">${title}${icon(ico)}</div><div class="metric-value"><strong>${fmt(value)}</strong></div><div class="metric-foot">${icon(emphasis ? "crosshair" : "check")}${foot}</div>${emphasis ? sparkline(data.trend) : ""}</article>`,
    )
    .join("");
  $("#activity-total").textContent = fmt(m.total);
  $("#activity-chart").innerHTML = lineChart(data.trend);
  drawDonut(data.severities);
  $("#department-chart").innerHTML = bars(data.departments, true);
  const known = data.countries.filter((c) => c.label !== "Unknown");
  $("#country-count").textContent = known.length;
  $("#top-country").textContent = known[0]?.label || "No network data";
  drawGlobe(known);
  const h = data.hosts[0];
  $("#priority-content").innerHTML = h
    ? `<div class="priority-host"><span class="host-icon">${icon("monitor")}</span><div><strong>${esc(h.hostname)}</strong><small>${esc(h.department)} · ${h.sources} observed sources</small></div></div><div class="priority-signals"><span><strong>${fmt(h.failures)}</strong>auth failures</span><span><strong>${fmt(h.endpoint_alerts)}</strong>endpoint alerts</span><span><strong>${fmt(h.threats)}</strong>threat flags</span></div><button class="priority-action" data-host="${esc(h.hostname)}">Investigate this host${icon("arrow-up-right")}</button>`
    : empty("Try widening your filters.");
  $("#recent-events").innerHTML = data.recent.length
    ? data.recent.map(eventRow).join("")
    : '<tr><td colspan="6">' + empty("No high-risk observations in this scope.") + "</td></tr>";
  renderHosts(data.hosts);
}
function eventRow(r) {
  return `<tr><td><div class="event-name"><span class="signal-icon">${icon(r.source === "endpoint" ? "shield" : r.source === "iam" ? "users" : "globe")}</span><div><strong>${esc(r.kind.replaceAll("_", " "))}</strong><small>${esc(r.id)}</small></div></div></td><td><span class="source-badge">${esc(r.source === "iam" ? "IAM" : r.source)}</span></td><td>${r.hostname ? `<button class="text-button" data-host="${esc(r.hostname)}">${esc(r.hostname)}</button>` : "Unresolved host"}${r.user_id ? `<small>${esc(r.user_id)}</small>` : ""}</td><td>${severity(r.severity)}</td><td>${esc(dateTime(r.timestamp))}</td><td><button class="icon-button" data-event="${esc(r.id)}" aria-label="Inspect event ${esc(r.id)}">${icon("arrow-up-right")}</button></td></tr>`;
}

// Orthographic globe: simplified land silhouettes are decorative; country counts come from telemetry.
function drawGlobe(countries) {
  const land = [
    [
      -168, 70, -145, 70, -125, 59, -123, 48, -115, 31, -98, 17, -82, 9, -81, 25, -65, 46, -54, 49, -61, 65,
      -100, 76,
    ],
    [-81, 11, -64, 10, -48, -1, -35, -8, -45, -24, -60, -55, -74, -48, -81, -12],
    [-17, 36, 10, 37, 34, 31, 43, 12, 51, 10, 40, -12, 32, -34, 18, -35, 9, -10, -5, 5, -17, 16],
    [
      -10, 36, -9, 58, 9, 71, 40, 70, 63, 76, 100, 76, 144, 65, 180, 65, 175, 50, 140, 40, 124, 23, 107, 1,
      96, 5, 79, 8, 69, 24, 50, 12, 37, 31, 21, 36,
    ],
    [112, -11, 134, -11, 153, -25, 145, -40, 116, -34],
    [-53, 60, -22, 64, -20, 82, -45, 84, -62, 73],
    [46, -13, 50, -16, 48, -25, 44, -24],
  ];
  const contains = (lon, lat, poly) => {
    let inside = false;
    for (let i = 0, j = poly.length - 2; i < poly.length; j = i, i += 2) {
      const a = poly[i],
        b = poly[i + 1],
        c = poly[j],
        d = poly[j + 1];
      if (b > lat !== d > lat && lon < ((c - a) * (lat - b)) / (d - b) + a) inside = !inside;
    }
    return inside;
  };
  const project = (lon, lat) => {
    const a = ((lon - 42) * Math.PI) / 180,
      b = (lat * Math.PI) / 180,
      t = (15 * Math.PI) / 180;
    const depth = Math.sin(b) * Math.sin(t) + Math.cos(b) * Math.cos(a) * Math.cos(t);
    return {
      x: 200 + 147 * Math.cos(b) * Math.sin(a),
      y: 148 - 147 * (Math.sin(b) * Math.cos(t) - Math.cos(b) * Math.cos(a) * Math.sin(t)),
      depth,
    };
  };
  let dots = "";
  for (let lat = -75; lat <= 80; lat += 3.2)
    for (let lon = -180; lon < 180; lon += 3.2) {
      const p = project(lon, lat);
      if (p.depth > 0.04 && land.some((poly) => contains(lon, lat, poly)))
        dots += `<circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="${(0.65 + p.depth * 0.48).toFixed(1)}" fill="#9cb96a" opacity="${(0.14 + p.depth * 0.29).toFixed(2)}"/>`;
    }
  const coordinates = {
    India: [79, 22],
    "United States": [-98, 39],
    China: [104, 35],
    Russia: [100, 60],
    Germany: [10, 51],
    "United Kingdom": [-2, 54],
    Brazil: [-51, -14],
    Australia: [134, -25],
    Singapore: [104, 1],
    Japan: [138, 37],
    Canada: [-106, 56],
    France: [2, 47],
    Netherlands: [5, 52],
    "South Korea": [128, 36],
  };
  let marks = "";
  countries.slice(0, 10).forEach((c) => {
    if (!coordinates[c.label]) return;
    const p = project(...coordinates[c.label]);
    if (p.depth < 0) return;
    marks += `<g><circle cx="${p.x}" cy="${p.y}" r="10" fill="#d5f478" opacity=".06"/><circle class="spark-pulse" cx="${p.x}" cy="${p.y}" r="6" fill="none" stroke="#d5f478" opacity=".3"/><circle cx="${p.x}" cy="${p.y}" r="2.4" fill="#ddff83"/><title>${esc(c.label)}: ${fmt(c.value)} firewall events</title></g>`;
  });
  $("#globe").innerHTML =
    `<svg viewBox="0 0 400 280" role="img" aria-label="Reported country locations on a decorative globe"><defs><radialGradient id="earth-light"><stop stop-color="#6e9340" stop-opacity=".06"/><stop offset=".85" stop-color="#5f7d36" stop-opacity=".01"/><stop offset="1" stop-color="#a5d861" stop-opacity=".09"/></radialGradient></defs><circle cx="200" cy="148" r="147" fill="url(#earth-light)" stroke="#8eb755" stroke-opacity=".08"/><ellipse cx="200" cy="148" rx="172" ry="57" fill="none" stroke="#778b57" stroke-opacity=".14" transform="rotate(-24 200 148)"/>${dots}${marks}</svg>`;
}
function networkSvg(host, signals) {
  const positions = { iam: [75, 75], endpoint: [345, 75], firewall: [210, 232] };
  const center = [210, 130];
  return `<svg viewBox="0 0 420 280" role="img" aria-label="${esc(host)} connected to observed data sources"><defs><radialGradient id="node-glow"><stop stop-color="#d5f478" stop-opacity=".12"/><stop offset="1" stop-color="#d5f478" stop-opacity="0"/></radialGradient></defs><circle cx="210" cy="130" r="90" fill="url(#node-glow)"/>${signals
    .map((s) => {
      const [x, y] = positions[s.label] || [210, 232];
      return `<path d="M${center[0]} ${center[1]} Q${x} ${center[1]} ${x} ${y}" fill="none" stroke="#7d9950" stroke-width="1" stroke-dasharray="4 5"/><g data-focus-source="${esc(s.label)}" tabindex="0" role="button" aria-label="Show ${esc(sourceNames[s.label])} evidence"><circle cx="${x}" cy="${y}" r="30" fill="#26341a" stroke="#5b743b"/><text x="${x}" y="${y + 3}" class="network-value" text-anchor="middle">${fmt(s.value)}</text><text x="${x}" y="${y + 45}" class="network-caption" text-anchor="middle">${esc(sourceNames[s.label])}</text><title>${s.high_risk || 0} high-risk signals</title></g>`;
    })
    .join(
      "",
    )}<rect x="149" y="110" width="122" height="42" rx="11" fill="#d5f478"/><text x="210" y="135" text-anchor="middle" fill="#27351a" font-family="Manrope,sans-serif" font-size="11" font-weight="600">${esc(host)}</text></svg>`;
}
function renderHosts(hosts) {
  $("#host-list").innerHTML = hosts.length
    ? hosts
        .map(
          (h) =>
            `<button class="host-row" data-host="${esc(h.hostname)}"><span class="host-icon">${icon("monitor")}</span><span class="host-info"><strong>${esc(h.hostname)}</strong><small>${esc(h.department)} · ${h.sources} sources · ${fmt(h.events)} events</small></span><span class="host-score">${fmt(h.high_risk)}<small>high-risk signals</small></span>${icon("arrow-up-right")}</button>`,
        )
        .join("")
    : empty("No observed hosts in this scope.");
  if (hosts[0])
    $("#network-preview").innerHTML =
      networkSvg(hosts[0].hostname, [
        { label: "iam", value: hosts[0].failures },
        { label: "endpoint", value: hosts[0].endpoint_alerts },
        { label: "firewall", value: hosts[0].threats },
      ]) +
      '<p class="source-note">Counts: authentication failures, endpoint alerts, firewall threat flags.</p>';
  else $("#network-preview").innerHTML = "";
}
async function refresh() {
  const sequence = ++state.sequence;
  error("");
  $("#reset-filters").classList.toggle(
    "hidden",
    JSON.stringify(filters()) === JSON.stringify({ period: "30", source: "all", department: "all" }),
  );
  try {
    const data = await api("/api/dashboard?" + params(filters()));
    if (sequence !== state.sequence) return;
    state.data = data;
    renderOverview(data);
    if (state.meta) {
      const end = state.meta.latest.slice(0, 10);
      let start = state.meta.earliest.slice(0, 10);
      if (filters().period !== "all") {
        const d = new Date(end + "T00:00:00Z");
        d.setUTCDate(d.getUTCDate() - Number(filters().period) + 1);
        start = d.toISOString().slice(0, 10);
      }
      $("#date-range").textContent = `${shortDate(start)} – ${shortDate(end)}, ${end.slice(0, 4)} · UTC`;
    }
    if (state.view === "events") await loadEvents();
  } catch (e) {
    if (sequence === state.sequence) error(e.message);
  }
}
async function switchView(view) {
  if (!views[view]) return;
  state.view = view;
  const [title, heading, description, eyebrow] = views[view];
  $$(".view").forEach((el) => el.classList.toggle("active", el.id === "view-" + view));
  $$(".nav-item").forEach((el) => {
    const active = el.dataset.view === view;
    el.classList.toggle("active", active);
    if (active) el.setAttribute("aria-current", "page");
    else el.removeAttribute("aria-current");
  });
  $("#breadcrumb").textContent = title;
  $("#page-title").innerHTML = heading;
  $("#page-description").textContent = description;
  $(".page-heading .eyebrow").textContent = eyebrow;
  $("#ask-top").classList.toggle("hidden", view === "assistant");
  $(".filterbar").classList.toggle("hidden", ["quality", "cases"].includes(view));
  history.replaceState(null, "", "#" + view);
  error("");
  try {
    if (view === "events") await loadEvents();
    if (view === "quality") await loadQuality();
    if (view === "cases") await loadCases();
  } catch (e) {
    error(e.message);
  }
}
async function loadEvents() {
  const sequence = ++state.eventSequence;
  const data = await api("/api/events?" + params({ ...eventFilters(), page: state.page }));
  if (sequence !== state.eventSequence) return;
  state.pages = data.pages;
  $("#event-rows").innerHTML = data.rows.length
    ? data.rows.map(eventRow).join("")
    : '<tr><td colspan="6">' + empty("Try another search or clear your filters.") + "</td></tr>";
  $("#event-total").textContent = `${fmt(data.total)} matching events`;
  $("#page-number").textContent = `${data.page} / ${fmt(data.pages)}`;
  $("#prev-page").disabled = data.page <= 1;
  $("#next-page").disabled = data.page >= data.pages;
}
function showDrawer(html) {
  $("#drawer-content").innerHTML = html;
  const dialog = $("#investigation-dialog");
  if (!dialog.open) dialog.showModal();
  dialog.scrollTop = 0;
}
async function openHost(hostname, override = null) {
  const hostArgs = override || filters();
  state.host = hostname;
  state.hostArgs = hostArgs;
  showDrawer(
    `<div class="drawer-header"><h2>${esc(hostname)}</h2><button class="icon-button close-dialog" aria-label="Close investigation">${icon("x")}</button></div><div class="empty">Loading connected evidence…</div>`,
  );
  try {
    const data = await api("/api/investigate/" + encodeURIComponent(hostname) + "?" + params(hostArgs));
    if (state.host !== hostname) return;
    state.hostData = data;
    const identity = data.identity[0],
      s = data.summary;
    showDrawer(
      `<div class="drawer-header"><div><span class="eyebrow lime">HOST INVESTIGATION</span><h2 id="drawer-title">${esc(hostname)}</h2><p>${fmt(s.events)} observations · ${s.sources} sources · ${hostArgs.period === "all" ? "All time" : "Last " + esc(hostArgs.period) + " days"} · ${esc(hostArgs.source === "all" ? "All sources" : sourceNames[hostArgs.source])}</p></div><button class="icon-button close-dialog" aria-label="Close investigation">${icon("x")}</button></div><div class="drawer-body">${identity ? `<div class="identity-info"><div><h3>${esc(identity.full_name)}</h3><p>${esc(identity.user_id)} · ${esc(identity.department)} · ${esc(identity.role)}</p></div><span class="source-badge">${esc(identity.status)}</span></div>` : "<p>No matching host in the identity master.</p>"}<div class="drawer-kpis"><div><strong>${fmt(s.failures)}</strong><small>Authentication failures</small></div><div><strong>${fmt(s.endpoint_alerts)}</strong><small>Endpoint alerts</small></div><div><strong>${fmt(s.threats)}</strong><small>Firewall threat flags</small></div></div><div class="evidence-graph">${networkSvg(hostname, data.signals)}</div><div class="info-note">${icon("info")}${esc(data.caveat)}</div><section class="drawer-section"><h3>Track this investigation</h3><form id="case-form" class="case-form"><label>Status<select name="status"><option>Watching</option><option>Investigating</option><option>Closed</option></select></label><label>Analyst note<textarea name="note" maxlength="2000" placeholder="What did you observe? What should happen next?">${esc(data.case?.note || "")}</textarea></label><button class="button primary" type="submit">${icon("bookmark")}Save investigation</button></form></section><section class="drawer-section"><div class="card-heading" style="padding:0 0 18px"><h3>Evidence timeline</h3><button class="text-button" id="all-timeline">Show all sources</button></div><div id="timeline">${timelineHtml(data.timeline)}</div></section></div>`,
    );
    if (data.case) $("#case-form select").value = data.case.status;
    $("#case-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const button = $("button", e.currentTarget);
      button.disabled = true;
      try {
        await post("/api/cases", {
          hostname,
          status: $("#case-form select").value,
          note: $("#case-form textarea").value,
        });
        toast("Investigation saved");
        await loadCases();
      } catch (err) {
        toast(err.message);
      } finally {
        button.disabled = false;
      }
    });
  } catch (e) {
    showDrawer(
      `<div class="drawer-header"><h2 id="drawer-title">Investigation unavailable</h2><button class="icon-button close-dialog" aria-label="Close investigation">${icon("x")}</button></div>${empty(e.message)}`,
    );
  }
}
function timelineHtml(rows) {
  return rows.length
    ? rows
        .map(
          (r) =>
            `<div class="timeline-item"><time>${esc(dateTime(r.timestamp))} · ${esc(sourceNames[r.source])}</time><h4>${esc(r.kind.replaceAll("_", " "))}</h4><p>${esc(r.user_id || "Unresolved identity")} ${r.source_ip ? "· " + esc(r.source_ip) : ""}</p><button class="text-button timeline-id" data-event="${esc(r.id)}">${esc(r.id)} ${icon("arrow-up-right")}</button>${r.quality_flags ? `<div class="quality-warning">${esc(r.quality_flags)}</div>` : ""}</div>`,
        )
        .join("")
    : empty("No events from this source in the most recent 80 observations.");
}
async function openEvent(id) {
  state.host = null;
  showDrawer(
    `<div class="drawer-header"><h2 id="drawer-title">Event evidence</h2><button class="icon-button close-dialog" aria-label="Close evidence">${icon("x")}</button></div><div class="empty">Loading event…</div>`,
  );
  try {
    const data = await api("/api/event/" + encodeURIComponent(id)),
      r = data.event;
    showDrawer(
      `<div class="drawer-header"><div><span class="eyebrow lime">CLEANED SOURCE RECORD</span><h2 id="drawer-title">${esc(id)}</h2><p>${esc(sourceNames[r.source])} · ${esc(dateTime(r.timestamp))}</p></div><button class="icon-button close-dialog" aria-label="Close evidence">${icon("x")}</button></div><div class="drawer-body"><div class="identity-info"><h3>${esc(r.kind.replaceAll("_", " "))}</h3>${severity(r.severity)}</div>${r.quality_flags ? `<div class="info-note">${icon("alert")}${esc(r.quality_flags)}</div>` : ""}<p class="source-note">Stable event ID retained from the organizer's source. Values below are normalized; original records remain in the source files.</p><div class="table-wrap"><table class="quality-table"><thead><tr><th>FIELD</th><th>CLEANED VALUE</th></tr></thead><tbody>${Object.entries(
        data.cleaned,
      )
        .map(
          ([key, value]) =>
            `<tr><td>${esc(key)}</td><td style="white-space:normal;overflow-wrap:anywhere;max-width:300px">${esc(value === null ? "Null / unresolved" : typeof value === "boolean" ? String(value) : value)}</td></tr>`,
        )
        .join(
          "",
        )}</tbody></table></div>${r.hostname ? `<button class="button primary" style="margin-top:24px" data-host="${esc(r.hostname)}">${icon("network")}Investigate ${esc(r.hostname)}</button>` : ""}</div>`,
    );
  } catch (e) {
    toast(e.message);
    $("#investigation-dialog").close();
  }
}
async function loadCases() {
  const data = await api("/api/cases");
  $("#case-count").textContent = data.rows.filter((r) => r.status !== "Closed").length;
  $("#case-list").innerHTML = data.rows.length
    ? data.rows
        .sort((a, b) => b.updated_at.localeCompare(a.updated_at))
        .map(
          (r) =>
            `<div class="case-row"><span class="host-icon">${icon("bookmark")}</span><div><h3>${esc(r.hostname)} <span class="source-badge">${esc(r.status)}</span></h3><p>${esc(r.note || "No analyst note yet.")}</p><small>Updated ${esc(r.updated_at)} UTC</small></div><button class="button secondary compact" data-case-host="${esc(r.hostname)}">Open evidence${icon("arrow-up-right")}</button></div>`,
        )
        .join("")
    : empty(
        "Open a host from Threat connections and save an investigation to start your queue.",
        "A clear queue. A good place to start.",
      );
}
async function loadQuality() {
  const q = await api("/api/quality");
  const removed = q.raw_rows - q.clean_rows;
  $("#quality-content").innerHTML = `<div class="metrics quality-metrics">${[
    ["Source records", q.raw_rows, "Across four supplied files"],
    ["Clean records", q.clean_rows, "Including the identity master"],
    ["Duplicate / key removals", removed, "Deterministic primary-key deduplication"],
    ["Flagged telemetry", q.flagged_events, "One or more unresolved quality flags"],
  ]
    .map(
      ([title, value, note]) =>
        `<div class="card metric"><div class="metric-head">${title}${icon("database")}</div><div class="metric-value"><strong>${fmt(value)}</strong></div><div class="metric-foot">${note}</div></div>`,
    )
    .join(
      "",
    )}</div><article class="card"><div class="card-heading"><div><h2>From fragmented data to an analytical model</h2><p>Reproducible transformations · source hashes recorded · original data preserved</p></div><span class="micro-badge">PIPELINE COMPLETE</span></div><div class="quality-pipeline">${[
    ["layers", "Ingest", "CSV + JSON + XLSX"],
    ["code", "Normalize", "IDs, labels & timestamps"],
    ["shield", "Validate", "Nulls, keys & chronology"],
    ["database", "Model", "DuckDB + SQL views"],
  ]
    .map(
      ([ico, title, desc], i) =>
        `${i ? '<span class="pipeline-arrow">' + icon("arrow-right") + "</span>" : ""}<div class="pipeline-stage">${icon(ico)}<strong>${title}</strong><small>${desc}</small></div>`,
    )
    .join("")}</div></article><div class="quality-sources" style="margin-top:18px">${q.sources
    .map(
      (s) =>
        `<article class="card quality-source"><h3>${esc(sourceNames[s.source] || "Identity & asset master")}</h3><p>${esc(s.file)}</p><div class="source-counts"><div><strong>${fmt(s.raw)}</strong><small>source rows</small></div><div><strong class="lime">${fmt(s.clean)}</strong><small>clean rows</small></div><div><strong>${fmt(s.duplicates)}</strong><small>duplicates removed</small></div></div><details><summary>Inspect field transformations</summary><table class="quality-table"><thead><tr><th>FIELD</th><th>CHANGED</th><th>SET TO NULL</th></tr></thead><tbody>${Object.keys(
          s.changed,
        )
          .map((k) => `<tr><td>${esc(k)}</td><td>${fmt(s.changed[k])}</td><td>${fmt(s.invalid[k])}</td></tr>`)
          .join(
            "",
          )}</tbody></table><p class="source-note">Counts measured before deduplication. Changed includes type and format normalization. ${fmt(s.missing_ids)} rows removed for missing primary keys.</p></details><details><summary>Source fingerprint · SHA-256</summary><pre>${esc(s.sha256)}</pre></details></article>`,
    )
    .join(
      "",
    )}</div><article class="card quality-policies"><h2>The gaps are part of the story.</h2><p><strong class="lime">${fmt(q.invalid_resolutions)} impossible resolution timestamps</strong> were cleared and explicitly flagged; they are excluded from resolution-time metrics. <strong class="lime">${fmt(q.unmatched_events)} telemetry events</strong> could not be matched to an identity. They remain available for investigation.</p><p>${esc(q.timestamp_policy)}</p><p>Master identity departments take precedence over telemetry labels. Unsupported numeric risk labels remain null; IAM event-based fallback scores are flagged. The application does not infer missing IP addresses, invent identities, or treat host correlation as causation.</p><p class="source-note">Last pipeline build: ${esc(q.built_at)} · Run <code>python pipeline.py</code> to rebuild from source.</p></article>`;
}
async function ask(question) {
  const button = $("#ask-form button");
  if (button.disabled) return;
  button.disabled = true;
  $("#question").value = question;
  const result = document.createElement("article");
  result.className = "agent-result";
  result.innerHTML = `<div class="question-bubble">${esc(question)}</div><div class="agent-busy">${icon("sparkles")}Reading the evidence and preparing your chart…</div>`;
  $("#agent-results").append(result);
  $(".agent-welcome").classList.add("hidden");
  try {
    const data = await post("/api/ask", { question, ...filters() });
    result.innerHTML = `<div class="question-bubble">${esc(question)}</div><div class="answer-engine">${icon("sparkles")}${esc(data.engine)}</div><h3>${esc(data.title)}</h3><p>${esc(data.answer)}</p>${data.warning ? `<div class="info-note">${esc(data.warning)}</div>` : ""}<div class="answer-chart">${data.chart === "line" ? lineChart(data.rows, "value", null) : bars(data.rows)}</div><details><summary>Inspect SQL & scope</summary><pre>${esc(data.sql)}\n\nParameters: ${esc(JSON.stringify(data.parameters))}\nFilters: ${esc(JSON.stringify(data.scope))}</pre></details><p class="answer-note">${esc(data.note)}</p><button class="text-button chart-download">${icon("download")}Download answer data</button>`;
    $(".chart-download", result).addEventListener("click", () => downloadJson(data));
    $("#question").value = "";
  } catch (e) {
    result.innerHTML = `<div class="question-bubble">${esc(question)}</div><div class="info-note">${icon("info")}${esc(e.message)}</div>`;
  } finally {
    button.disabled = false;
    result.scrollIntoView({
      behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
      block: "nearest",
    });
    $("#question").focus({ preventScroll: true });
  }
}
function downloadJson(data) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = "sentinel-answer.json";
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

document.addEventListener("click", async (e) => {
  const view = e.target.closest("[data-view]");
  if (view) {
    await switchView(view.dataset.view);
    return;
  }
  const department = e.target.closest("[data-department]");
  if (department) {
    $("#department").value = department.dataset.department;
    state.page = 1;
    await refresh();
    return;
  }
  const close = e.target.closest(".close-dialog");
  if (close) {
    close.closest("dialog").close();
    return;
  }
  const saved = e.target.closest("[data-case-host]");
  if (saved) {
    await openHost(saved.dataset.caseHost, { period: "all", source: "all", department: "all" });
    return;
  }
  const host = e.target.closest("[data-host]");
  if (host) {
    await openHost(host.dataset.host);
    return;
  }
  const event = e.target.closest("[data-event]");
  if (event) {
    await openEvent(event.dataset.event);
    return;
  }
  const question = e.target.closest("[data-question]");
  if (question) {
    await ask(question.dataset.question);
    return;
  }
  const source = e.target.closest("[data-focus-source]");
  if (source) {
    if (source.closest("#investigation-dialog") && state.hostData) {
      $("#timeline").innerHTML = timelineHtml(
        state.hostData.timeline.filter((r) => r.source === source.dataset.focusSource),
      );
      $("#timeline").scrollIntoView({ block: "start" });
    } else if (state.data?.hosts[0]) await openHost(state.data.hosts[0].hostname);
    return;
  }
  if (e.target.closest("#all-timeline") && state.hostData)
    $("#timeline").innerHTML = timelineHtml(state.hostData.timeline);
});
$("#ask-top").addEventListener("click", () => switchView("assistant").then(() => $("#question").focus()));
$("#ask-form").addEventListener("submit", (e) => {
  e.preventDefault();
  ask($("#question").value.trim());
});
["period", "source", "department"].forEach((id) =>
  $("#" + id).addEventListener("change", () => {
    state.page = 1;
    refresh();
  }),
);
$("#reset-filters").addEventListener("click", () => {
  $("#period").value = "30";
  $("#source").value = "all";
  $("#department").value = "all";
  state.page = 1;
  refresh();
});
$("#export").addEventListener("click", async () => {
  const button = $("#export");
  button.disabled = true;
  try {
    const response = await fetch(
      "/api/export?" + params(state.view === "events" ? eventFilters() : filters()),
    );
    if (!response.ok) throw new Error("Export failed. Please retry.");
    const url = URL.createObjectURL(await response.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download = "sentinel-evidence.csv";
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast("Evidence export downloaded");
  } catch (e) {
    toast(e.message);
  } finally {
    button.disabled = false;
  }
});
$("#globe-explore").addEventListener("click", async () => {
  $("#source").value = "firewall";
  state.page = 1;
  await switchView("events");
  refresh();
});
$("#severity-filter").addEventListener("change", () => {
  state.page = 1;
  loadEvents().catch((e) => error(e.message));
});
let searchTimer;
$("#event-search").addEventListener("input", () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    state.page = 1;
    loadEvents().catch((e) => error(e.message));
  }, 250);
});
$("#prev-page").addEventListener("click", () => {
  if (state.page > 1) {
    state.page--;
    loadEvents().catch((e) => error(e.message));
  }
});
$("#next-page").addEventListener("click", () => {
  if (state.page < state.pages) {
    state.page++;
    loadEvents().catch((e) => error(e.message));
  }
});
const focusSearch = async () => {
  await switchView("events");
  $("#event-search").focus();
};
$("#shortcuts").addEventListener("click", focusSearch);
$("#about-button").addEventListener("click", () => $("#about-dialog").showModal());
document.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
    e.preventDefault();
    focusSearch();
  }
  if (e.key === "Enter" && e.target.matches("[data-focus-source]"))
    e.target.dispatchEvent(new MouseEvent("click", { bubbles: true }));
});
$$("dialog").forEach((dialog) =>
  dialog.addEventListener("click", (e) => {
    if (e.target === dialog) {
      const r = dialog.getBoundingClientRect();
      if (e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom)
        dialog.close();
    }
  }),
);
async function initialize() {
  icons();
  try {
    state.meta = await api("/api/meta");
    $("#department").innerHTML =
      '<option value="all">All departments</option>' +
      state.meta.departments.map((d) => `<option>${esc(d)}</option>`).join("");
    $("#agent-engine").textContent = state.meta.agent;
    await refresh();
    await switchView(location.hash.slice(1) || "overview");
    await loadCases();
  } catch (e) {
    error("Unable to load the workspace: " + e.message);
  }
}
initialize();
