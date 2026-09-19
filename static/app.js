// app.js — talks to the API and renders what comes back. No dependencies.
//
// Every value shown here arrives from the server. If a number appears on
// screen, the detector computed it during this session.
"use strict";

const $ = (id) => document.getElementById(id);

const el = {
  text: $("logtext"), dropzone: $("dropzone"), file: $("fileinput"),
  clear: $("clear"), lines: $("linecount"), hint: $("input-hint"),
  samples: $("samples"), samplesWrap: $("samples-wrap"),
  samplesToggle: $("samples-toggle"), provenance: $("provenance"),
  genHours: $("gen-hours"), genSeed: $("gen-seed"), generate: $("generate"),
  verify: $("verify"), genResult: $("gen-result"),
  threshold: $("threshold"), window: $("window"), minFailures: $("min-failures"),
  allowlist: $("allowlist"), compromise: $("detect-compromise"),
  sendAlerts: $("send-alerts"), alertAvailability: $("alert-availability"),
  geoLookup: $("geo-lookup"),
  presetHint: $("preset-hint"), analyze: $("analyze"),
  results: $("results"), error: $("error"), verdict: $("verdict"),
  stats: $("stats"), findings: $("findings"), suppressed: $("suppressed"),
  source: $("findings-source"), report: $("report"),
  timeline: $("timeline"), offenders: $("offenders"),
  lookupIp: $("lookup-ip"), lookupGo: $("lookup-go"),
  lookupMethods: $("lookup-methods"), lookupResult: $("lookup-result"),
  quickIps: $("quick-ips"),
  lookupRecent: $("lookup-recent"),
  livePath: $("live-path"), liveThreshold: $("live-threshold"),
  liveWindow: $("live-window"), liveFromStart: $("live-from-start"),
  liveStart: $("live-start"), liveStop: $("live-stop"), liveClear: $("live-clear"),
  liveState: $("live-state"), liveStats: $("live-stats"),
  liveFindings: $("live-findings"), liveActivity: $("live-activity"),
  liveUnconfigured: $("live-unconfigured"),
  livePill: $("live-pill"), livePillText: $("live-pill-text"),
  historyRefresh: $("history-refresh"), historyClear: $("history-clear"),
  historySummary: $("history-summary"), repeatOffenders: $("repeat-offenders"),
  recentRuns: $("recent-runs"), alertLog: $("alert-log"),
  setupRefresh: $("setup-refresh"), capabilities: $("capabilities"),
  backend: $("backend"),
  alertChannels: $("alert-channels"), alertTest: $("alert-test"),
  alertTestResult: $("alert-test-result"),
  theme: $("theme-toggle"), tabs: $("tabs"),
};

// Escape everything from the log before it reaches innerHTML. Log lines are
// attacker-controlled by definition — a username can contain markup.
const esc = (value) => String(value ?? "").replace(/[&<>"']/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;

async function api(path, options) {
  const response = await fetch(path, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `${path} → ${response.status}`);
  return data;
}

function ago(seconds) {
  if (!seconds || seconds < 0) return "just now";
  if (seconds < 60) return `${Math.round(seconds)}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}

// The last analysis, so the report button and the lookup tab have something
// to work from without re-asking the server what we just sent it.
let lastAnalysis = null;
let lastSeed = null;

// What is currently loaded. currentSample is set ONLY while an untouched
// bundled file is loaded — the moment the operator edits the box it must go
// back to null, or "Analyse" would keep re-running the sample and quietly
// ignore what they actually typed.
let currentSample = null;
let currentName = null;

// ── tabs ────────────────────────────────────────────────────

el.tabs.addEventListener("click", (event) => {
  const button = event.target.closest(".tab");
  if (!button) return;
  const wanted = button.dataset.tab;
  document.querySelectorAll(".tab").forEach((t) =>
    t.setAttribute("aria-selected", String(t === button)));
  document.querySelectorAll(".tabpanel").forEach((p) => {
    p.hidden = p.dataset.panel !== wanted;
  });
  if (wanted === "history") loadHistory();
  if (wanted === "setup") { loadSetup(); loadBackend(); }
  if (wanted === "lookup") renderRecentAddresses();
});

// ── input ───────────────────────────────────────────────────

function updateLineCount() {
  const text = el.text.value.trim();
  const n = text ? text.split("\n").length : 0;
  el.lines.textContent = plural(n, "line");
}

el.text.addEventListener("input", () => {
  updateLineCount();
  // Whatever is in the box now is the operator's, not the sample's.
  currentSample = null;
  currentName = null;
  if (el.text.value.trim()) markReady("edited"); else clearReady();
  document.querySelectorAll(".sample[aria-pressed=true]")
    .forEach((b) => b.setAttribute("aria-pressed", "false"));
});

// Clear means clear: input, results, verdict, charts, the generator panel,
// and the remembered analysis the report button would otherwise still use.
el.clear.addEventListener("click", () => {
  el.text.value = "";
  updateLineCount();
  lastAnalysis = null;
  lastSeed = null;
  currentSample = null;
  currentName = null;
  el.results.hidden = true;
  el.error.hidden = true;
  el.verdict.hidden = true;
  el.genResult.hidden = true;
  el.verify.disabled = true;
  el.stats.innerHTML = "";
  el.findings.innerHTML = "";
  el.suppressed.innerHTML = "";
  el.timeline.innerHTML = "";
  el.offenders.innerHTML = "";
  el.source.textContent = "";
  el.lookupResult.hidden = true;
  document.querySelectorAll(".sample[aria-pressed=true]")
    .forEach((b) => b.setAttribute("aria-pressed", "false"));
  renderRecentAddresses();
  clearReady();
  el.hint.textContent = "Drop a file, choose one, or paste lines";
});

el.samplesToggle.addEventListener("click", () => {
  el.samplesWrap.hidden = !el.samplesWrap.hidden;
  el.samplesToggle.textContent = el.samplesWrap.hidden ? "Show" : "Hide";
});

// Sample cards, built from stats the server computed by analysing each file.
async function loadSamples() {
  try {
    const payload = await api("/api/samples");
    el.provenance.innerHTML =
      `<strong>Where this data comes from.</strong> ${esc(payload.provenance)}`;

    const groups = {};
    payload.samples.forEach((s) => {
      (groups[s.group] = groups[s.group] || []).push(s);
    });
    const titles = { examples: "Start here — the two example logs",
                     quick: "Quick samples", clean: "Clean — should find nothing",
                     attacks: "Attacks — one technique each",
                     generated: "Generated" };

    const order = ["examples", "quick", "clean", "tricky", "attacks", "generated"];
    const ordered = order.filter((g) => groups[g])
      .concat(Object.keys(groups).filter((g) => !order.includes(g)));

    el.samples.innerHTML = ordered.map((group) => `
      <div class="sample-group">
        <h3>${esc(titles[group] || group)}</h3>
        <div class="sample-grid">
          ${groups[group].map((s) => `
            <button class="sample" type="button" data-sample="${esc(s.name)}">
              <strong>${esc(s.label)}</strong>
              <small>${esc(s.name)}</small>
              <span class="sample-stats">
                <span>${s.lines} lines</span>
                <span class="${s.high ? "bad" : s.findings ? "warn" : "good"}">
                  ${s.findings ? plural(s.findings, "finding") : "clean"}${s.high ? ` · ${s.high} high` : ""}
                </span>
              </span>
            </button>`).join("")}
        </div>
      </div>`).join("");
  } catch (err) {
    el.samples.innerHTML = `<p class="hint">Could not load samples: ${esc(err.message)}</p>`;
  }
}

el.samples.addEventListener("click", async (event) => {
  const button = event.target.closest(".sample");
  if (!button) return;
  const name = button.dataset.sample;
  try {
    const data = await api(`/api/samples/${encodeURIComponent(name)}`);
    el.text.value = data.text;
    updateLineCount();
    document.querySelectorAll(".sample").forEach((b) =>
      b.setAttribute("aria-pressed", String(b === button)));
    el.hint.textContent = `Loaded demo file ${name}`;
    el.verify.disabled = true;
    currentSample = name;
    currentName = null;
    markReady(`${name} loaded`);
  } catch (err) { showError(err.message); }
});

// ── generator ───────────────────────────────────────────────

el.generate.addEventListener("click", async () => {
  el.generate.disabled = true;
  el.generate.textContent = "Generating…";
  try {
    const data = await api("/api/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        hours: Number(el.genHours.value) || 24,
        seed: el.genSeed.value === "" ? null : Number(el.genSeed.value),
      }),
    });
    lastSeed = data.seed;
    el.genSeed.value = data.seed ?? "";
    el.text.value = data.text;
    updateLineCount();
    el.hint.textContent = `Generated ${data.lines} lines over ${data.hours}h`;
    el.verify.disabled = data.seed === null;
    currentSample = "generated.log";
    currentName = null;
    markReady(`${data.lines} lines generated`);

    el.genResult.hidden = false;
    el.genResult.innerHTML = `
      <strong>${plural(data.planted.length, "attack")} planted in ${data.lines} lines</strong>
      <ul>${data.planted.map((a) =>
        `<li><span class="planted">${esc(a.name)}</span> — ${esc(a.description)}</li>`).join("")}</ul>
      <p class="hint">The detector is not told any of this. Use
         <em>Score vs. ground truth</em> to see what it finds on its own.</p>`;
    loadSamples();
  } catch (err) {
    showError(err.message);
  } finally {
    el.generate.disabled = false;
    el.generate.textContent = "Generate";
  }
});

el.verify.addEventListener("click", async () => {
  if (lastSeed === null) return;
  el.verify.disabled = true;
  el.verify.textContent = "Scoring…";
  try {
    const data = await api("/api/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        seed: lastSeed, hours: Number(el.genHours.value) || 24,
        ...tuning(),
      }),
    });
    el.genResult.hidden = false;
    el.genResult.innerHTML = `
      <strong>Scored at threshold ${data.threshold} / ${data.window}s</strong>
      <div class="score">
        <span class="${data.caught === data.planted ? "good" : "warn"}">caught ${data.caught}/${data.planted}</span>
        <span class="${data.false_alarms.length ? "warn" : "good"}">${plural(data.false_alarms.length, "false alarm")}</span>
        <span>precision ${data.precision.toFixed(3)}</span>
        <span>recall ${data.recall.toFixed(3)}</span>
      </div>
      <ul>${data.attacks.map((a) => `
        <li><span class="${a.found ? "good" : "bad"}">${a.found ? "FOUND " : "MISSED"}</span>
            ${esc(a.name)}${a.matched_on.length ? ` — matched on <code>${esc(a.matched_on.join(", "))}</code>` : ""}</li>`).join("")}</ul>`;
    render(data.analysis);
  } catch (err) {
    showError(err.message);
  } finally {
    el.verify.disabled = false;
    el.verify.textContent = "Score vs. ground truth";
  }
});

// ── file input ──────────────────────────────────────────────

function loadFile(file) {
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    el.text.value = reader.result;
    updateLineCount();
    el.hint.textContent = `Loaded ${file.name} — nothing has been sent anywhere`;
    el.verify.disabled = true;
    currentSample = null;
    currentName = file.name;
    document.querySelectorAll(".sample[aria-pressed=true]")
      .forEach((b) => b.setAttribute("aria-pressed", "false"));
    markReady(`${file.name} loaded`);
  };
  reader.readAsText(file);
}

el.file.addEventListener("change", (e) => loadFile(e.target.files[0]));
["dragenter", "dragover"].forEach((type) =>
  el.dropzone.addEventListener(type, (e) => {
    e.preventDefault(); el.dropzone.classList.add("dragging");
  }));
["dragleave", "drop"].forEach((type) =>
  el.dropzone.addEventListener(type, (e) => {
    e.preventDefault(); el.dropzone.classList.remove("dragging");
  }));
el.dropzone.addEventListener("drop", (e) => loadFile(e.dataTransfer.files[0]));

// ── tuning ──────────────────────────────────────────────────

function bindSlider(input, output, suffix = "") {
  const sync = () => { output.textContent = input.value + suffix; };
  input.addEventListener("input", sync);
  sync();
}
bindSlider(el.threshold, $("threshold-out"));
bindSlider(el.window, $("window-out"), "s");
bindSlider(el.minFailures, $("min-failures-out"));

function tuning() {
  return {
    threshold: el.threshold.value,
    window: el.window.value,
    min_failures: el.minFailures.value,
    detect_compromise: el.compromise.checked,
    allowlist: el.allowlist.value,
    geo_lookup: el.geoLookup.checked,
  };
}

// Changing the tuning re-runs only if something has already been analysed.
// Loading a file never triggers analysis on its own — the operator decides
// when to run it, and on what.
[el.threshold, el.window, el.minFailures, el.compromise, el.allowlist,
 el.geoLookup].forEach((input) =>
  input.addEventListener("change", () => { if (lastAnalysis) analyze(); }));

// ── analysis ────────────────────────────────────────────────

// Content is loaded but not analysed yet. Say so, and draw the eye to the
// button that does it.
function markReady(what) {
  lastAnalysis = null;
  el.results.hidden = true;
  el.analyze.classList.add("ready");
  el.analyze.textContent = `Analyse log  →  ${what}`;
}

function clearReady() {
  el.analyze.classList.remove("ready");
  el.analyze.textContent = "Analyse log";
}

function showError(message) {
  el.results.hidden = false;
  el.error.hidden = false;
  el.verdict.hidden = true;
  el.error.textContent = message;
}

async function analyze(sampleName, fileName) {
  if (sampleName !== undefined) currentSample = sampleName;
  if (fileName !== undefined) currentName = fileName;

  const text = el.text.value;
  if (!text.trim()) return showError("Load or paste a log first.");

  el.analyze.disabled = true;
  el.analyze.classList.remove("ready");
  el.analyze.textContent = "Analysing…";
  try {
    const body = currentSample
      ? { sample: currentSample, ...tuning(), alert: el.sendAlerts.checked }
      : { text, ...tuning(), alert: el.sendAlerts.checked };
    const data = await api("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!currentSample && currentName) data.source = currentName;
    render(data);
    // A completed analysis changes the history, so keep it current rather
    // than showing whatever it looked like when the tab was last opened.
    if (!document.querySelector('.tabpanel[data-panel="history"]').hidden) {
      loadHistory();
    }
  } catch (err) {
    showError(err.message);
  } finally {
    el.analyze.disabled = false;
    clearReady();
  }
}

el.analyze.addEventListener("click", () => analyze());

// ── report ──────────────────────────────────────────────────

el.report.addEventListener("click", async () => {
  if (!lastAnalysis) return showError("Analyse a log first.");
  el.report.disabled = true;
  el.report.textContent = "Building…";
  try {
    const body = currentSample
      ? { sample: currentSample, ...tuning() }
      : { text: el.text.value, source: currentName || "pasted input", ...tuning() };
    const response = await fetch("/api/report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.error || `report → ${response.status}`);
    }
    const html = await response.text();
    // Open it in a tab rather than forcing a download: the point of a report
    // is that someone reads it, and it prints to PDF from there.
    const tab = window.open("", "_blank");
    if (tab) {
      tab.document.write(html);
      tab.document.close();
    } else {
      const url = URL.createObjectURL(new Blob([html], { type: "text/html" }));
      window.location.href = url;
    }
  } catch (err) {
    showError(err.message);
  } finally {
    el.report.disabled = false;
    el.report.textContent = "Generate report";
  }
});

// ── rendering ───────────────────────────────────────────────

function render(data) {
  lastAnalysis = data;
  el.results.hidden = false;
  el.error.hidden = true;
  el.source.textContent =
    `${data.source} · threshold ${data.threshold} / ${data.window}s`;

  renderVerdict(data);
  renderStats(el.stats, [
    { label: "Events", value: data.stats.events },
    { label: "Failures", value: data.stats.failures },
    { label: "Successes", value: data.stats.successes },
    { label: "Unique IPs", value: data.stats.unique_ips },
    { label: "Skipped", value: data.stats.skipped },
    { label: "Findings", value: data.stats.findings, cls: data.stats.findings ? "warn" : "good" },
    { label: "High severity", value: data.stats.high, cls: data.stats.high ? "danger" : "good" },
  ]);
  renderFindings(el.findings, data.findings);
  renderSuppressed(data);
  renderTimeline(data.timeline);
  renderOffenders(data.top_offenders, data.findings);
  renderRecentAddresses();
}

function renderVerdict(data) {
  el.verdict.hidden = false;
  if (data.stats.high) {
    el.verdict.className = "verdict breach";
    const keys = data.findings.filter((f) => f.severity === "HIGH")
      .map((f) => f.key).join(", ");
    el.verdict.innerHTML = `<strong>Confirmed compromise</strong>
      ${esc(keys)} authenticated successfully after repeated failures.
      Rotate those credentials and review what the session did.`;
  } else if (data.stats.findings) {
    el.verdict.className = "verdict attempts";
    el.verdict.innerHTML = `<strong>Attack attempts, no confirmed breach</strong>
      ${plural(data.stats.findings, "finding")} crossed the threshold.
      Nothing here shows a successful login following those failures.`;
  } else {
    el.verdict.className = "verdict clear";
    el.verdict.innerHTML = `<strong>No threats detected</strong>
      Nothing crossed ${data.threshold} failures within ${data.window}s.`;
  }
}

function renderStats(target, cards) {
  target.innerHTML = cards.map((c) => `
    <div class="stat ${c.cls || ""}">
      <div class="value">${esc(c.value)}</div>
      <div class="label">${esc(c.label)}</div>
    </div>`).join("");
}

function findingRow(f, extra = "") {
  const seen = f.times_seen > 0
    ? `<span class="chip warn">seen ${plural(f.times_seen, "time")} before</span>` : "";
  const src = f.enrichment && f.enrichment.geo_source === "online"
    ? ' <span class="src">via ip-api.com</span>' : "";
  const where = f.location
    ? `<span class="chip">${esc(f.location)}${src}</span>` : "";
  const lookup = f.pivot === "ip"
    ? `<button class="chip link" type="button" data-lookup="${esc(f.key)}">look up</button>` : "";
  return `
    <div class="finding">
      <span class="badge ${esc(f.severity)}">${esc(f.severity)}</span>
      <span class="pivot">${esc(f.pivot)}</span>
      <div>
        <div class="key">${esc(f.key)}</div>
        <div class="detail">${esc(f.detail)}</div>
        <div class="chips">${where}${seen}${lookup}${extra}</div>
      </div>
    </div>`;
}

function renderFindings(target, findings) {
  if (!findings.length) {
    target.innerHTML = `<div class="empty">No threats detected.
      <small>Nothing in this log crossed the configured threshold.</small></div>`;
    return;
  }
  target.innerHTML = findings.map((f) => findingRow(f)).join("");
}

function renderSuppressed(data) {
  const list = data.suppressed || [];
  if (!list.length) { el.suppressed.innerHTML = ""; return; }
  el.suppressed.innerHTML = `
    <div class="suppressed">
      <strong>${plural(list.length, "finding")} suppressed by your allowlist</strong>
      <span class="hint">Shown so nothing is hidden without a record.</span>
      ${list.map((f) => `<div class="sup-row">
          <span class="pivot">${esc(f.pivot)}</span>
          <span class="mono">${esc(f.key)}</span>
          <span class="detail">${esc(f.detail)}</span>
        </div>`).join("")}
    </div>`;
}

function renderTimeline(buckets) {
  if (!buckets.length) {
    el.timeline.innerHTML = `<p class="hint">No failures to plot.</p>`;
    return;
  }
  const peak = Math.max(...buckets.map((b) => b.failures), 1);
  el.timeline.innerHTML = buckets.map((b) => {
    const height = b.failures ? Math.max((b.failures / peak) * 100, 3) : 0;
    const hot = b.failures >= peak * 0.75 && b.failures > 0 ? " hot" : "";
    return `<div class="bar${hot}" style="height:${height}%"
              title="${esc(b.label)} — ${plural(b.failures, "failure")}"></div>`;
  }).join("");
}

function renderOffenders(offenders, findings) {
  if (!offenders.length) {
    el.offenders.innerHTML = `<p class="hint">No failed logins in this log.</p>`;
    return;
  }
  const flagged = new Set(findings.map((f) => f.key));
  const peak = Math.max(...offenders.map((o) => o.failures), 1);
  el.offenders.innerHTML = offenders.map((o) => `
    <div class="offender ${flagged.has(o.ip) ? "flagged" : ""}">
      <span class="ip" title="${esc(o.location || "")}">${esc(o.ip)}</span>
      <span class="track"><span class="fill" style="width:${(o.failures / peak) * 100}%"></span></span>
      <span class="n">${o.failures}</span>
    </div>`).join("");
}

// Clicking "look up" on a finding jumps to the lookup tab with it filled in.
document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-lookup]");
  if (!button) return;
  el.lookupIp.value = button.dataset.lookup;
  document.querySelector('.tab[data-tab="lookup"]').click();
  runLookup();
});

// ── IP lookup ───────────────────────────────────────────────

// The method checkboxes are rendered into the page by the server, so they
// exist whether or not this script runs. Nothing to build here.

function chosenMethods() {
  const picked = ["builtin"];
  el.lookupMethods.querySelectorAll("input[type=checkbox]:checked")
    .forEach((cb) => { if (cb.value !== "builtin") picked.push(cb.value); });
  return picked;
}

async function runLookup() {
  const ip = el.lookupIp.value.trim();
  if (!ip) return;
  el.lookupGo.disabled = true;
  el.lookupGo.textContent = "Looking…";
  try {
    const data = await api("/api/lookup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip, methods: chosenMethods() }),
    });
    const rows = Object.keys(data.methods).map((name) => {
      const m = data.methods[name];
      const fields = Object.keys(m.data || {})
        .filter((k) => !["ip", "routable", "version"].includes(k))
        .map((k) => `<tr><td class="k">${esc(k.replace(/_/g, " "))}</td>
                       <td class="mono">${esc(m.data[k])}</td></tr>`).join("");
      return `
        <div class="method-result ${m.ok ? "ok" : "off"}">
          <div class="method-head">
            <strong>${esc(name)}</strong>
            <span class="chip ${m.ok ? "good" : "warn"}">${m.ok ? "answered" : esc(m.error || "no data")}</span>
          </div>
          ${fields ? `<table class="kv">${fields}</table>` : ""}
        </div>`;
    }).join("");

    // Classification alone tells you what KIND of address it is, not where it
    // is. Saying "Public internet" and stopping there reads as a broken
    // feature, so be explicit about why there is no location and what would
    // produce one.
    const merged = data.merged || {};
    const located = merged.country || merged.city || merged.hostname
                    || merged.network_operator;
    const routable = data.classification && data.classification.routable;
    const asked = Object.keys(data.methods);
    let advice = "";

    if (!located && !routable) {
      advice = `<div class="advice">
        <strong>This address has no real-world location, by design.</strong>
        ${esc(data.classification.label)} — reserved ranges are not routed on
        the internet and belong to nobody. The demo logs use them deliberately
        so no real network is ever named. Try
        <button class="chip link" type="button" data-lookup="1.1.1.1">1.1.1.1</button>
        or an address from your own log.</div>`;
    } else if (!located && routable) {
      const missing = [];
      if (!asked.includes("online")) missing.push("Online lookup");
      if (!asked.includes("maxmind")) missing.push("MaxMind");
      advice = `<div class="advice">
        <strong>No location found for this address yet.</strong>
        Only the offline classification ran, which can tell you the address is
        routable but not where it is.
        ${missing.length ? `Tick <em>${esc(missing.join(" or "))}</em> above and
          look it up again.` : "Nothing further was returned."}</div>`;
    }

    el.lookupResult.hidden = false;
    el.lookupResult.innerHTML = `
      <div class="lookup-summary">
        <span class="mono big">${esc(data.ip)}</span>
        <span>${esc(data.summary)}</span>
      </div>
      ${advice}
      ${rows}`;
  } catch (err) {
    el.lookupResult.hidden = false;
    el.lookupResult.innerHTML = `<p class="hint">${esc(err.message)}</p>`;
  } finally {
    el.lookupGo.disabled = false;
    el.lookupGo.textContent = "Look up";
  }
}

el.lookupGo.addEventListener("click", runLookup);
el.lookupIp.addEventListener("keydown", (e) => { if (e.key === "Enter") runLookup(); });

function renderRecentAddresses() {
  const offenders = (lastAnalysis && lastAnalysis.top_offenders) || [];
  if (!offenders.length) {
    el.lookupRecent.innerHTML = `<p class="hint">Analyse a log first, then its
      addresses appear here to click.</p>`;
    return;
  }
  const flagged = new Set((lastAnalysis.findings || []).map((f) => f.key));
  el.lookupRecent.innerHTML = offenders.map((o) => `
    <button class="addr ${flagged.has(o.ip) ? "flagged" : ""}" type="button"
            data-lookup="${esc(o.ip)}">
      <span class="mono">${esc(o.ip)}</span>
      <span class="hint">${plural(o.failures, "failure")} · ${esc(o.location || "")}</span>
    </button>`).join("");
}

// ── live monitor ────────────────────────────────────────────

let stream = null;
const liveFindings = [];
let liveStatus = {};

function setLivePill(status) {
  const on = status && status.running;
  el.livePill.hidden = !on;
  el.livePillText.textContent = status ? status.state : "live";
  el.livePill.className = `pill ${status && status.state === "running" ? "on" : "warn"}`;
  el.liveStart.disabled = !!on;
  el.liveStop.disabled = !on;
  el.liveState.textContent = status
    ? `${status.state}${status.error ? " — " + status.error : ""}`
    : "stopped";
}

// Takes the full watcher status. Merged into what we already know rather
// than replacing it, so a partial update cannot blank the counters.
function renderLiveStats(update) {
  liveStatus = { ...liveStatus, ...(update || {}) };
  renderStats(el.liveStats, [
    { label: "Lines read", value: liveStatus.lines_read ?? 0 },
    { label: "Skipped", value: liveStatus.lines_skipped ?? 0 },
    { label: "In window", value: liveStatus.events_buffered ?? 0 },
    { label: "Findings", value: liveStatus.findings_emitted ?? 0,
      cls: liveStatus.findings_emitted ? "warn" : "good" },
    { label: "Uptime", value: liveStatus.uptime_seconds
        ? ago(liveStatus.uptime_seconds).replace(" ago", "") : "—" },
  ]);
}

function pushActivity(text) {
  const stamp = new Date().toLocaleTimeString();
  const line = `<div class="feed-line"><span class="t">${esc(stamp)}</span> ${esc(text)}</div>`;
  if (el.liveActivity.querySelector(".hint")) el.liveActivity.innerHTML = "";
  el.liveActivity.insertAdjacentHTML("afterbegin", line);
  while (el.liveActivity.children.length > 60) el.liveActivity.lastElementChild.remove();
}

function pushLiveFinding(payload) {
  const f = payload.finding;
  f.location = payload.context && payload.context.location;
  f.times_seen = (payload.context && payload.context.times_seen) || 0;
  const alerts = (payload.alerts || [])
    .map((a) => `<span class="chip ${a.ok ? "good" : "warn"}">${esc(a.channel)}: ${a.ok ? "alerted" : esc(a.reason)}</span>`)
    .join("");
  liveFindings.unshift(findingRow(f, alerts));
  while (liveFindings.length > 50) liveFindings.pop();
  el.liveFindings.innerHTML = liveFindings.join("");
}

function openStream() {
  if (stream) stream.close();
  stream = new EventSource("/api/live/stream");
  stream.onmessage = (event) => {
    const message = JSON.parse(event.data);
    if (message.type === "state") {
      setLivePill(message.data);
      renderLiveStats(message.data);
    } else if (message.type === "activity") {
      const d = message.data;
      pushActivity(`read ${plural(d.lines, "line")} → ${d.events} events, ${d.skipped} skipped, ${d.buffered} in window`);
      renderLiveStats({ events_buffered: d.buffered });
      refreshLiveStatus();
    } else if (message.type === "finding") {
      pushLiveFinding(message.data);
      pushActivity(`FINDING ${message.data.finding.severity} ${message.data.finding.key}`);
      refreshLiveStatus();
    }
  };
  stream.onerror = () => pushActivity("stream interrupted — retrying");
}

async function refreshLiveStatus() {
  try {
    const status = await api("/api/live/status");
    setLivePill(status);
    if (status.running) renderLiveStats(status);
  } catch { /* not running */ }
}

el.liveStart.addEventListener("click", async () => {
  el.liveStart.disabled = true;
  try {
    const status = await api("/api/live/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        path: el.livePath.value.trim(),
        threshold: el.liveThreshold.value,
        window: el.liveWindow.value,
        allowlist: el.allowlist.value,
        from_end: !el.liveFromStart.checked,
      }),
    });
    el.liveUnconfigured.hidden = true;
    liveStatus = {};
    setLivePill(status);
    renderLiveStats(status);
    pushActivity(`following ${status.path}`);
    openStream();
  } catch (err) {
    el.liveUnconfigured.hidden = false;
    el.liveUnconfigured.innerHTML = esc(err.message);
    el.liveStart.disabled = false;
  }
});

el.liveStop.addEventListener("click", async () => {
  if (stream) { stream.close(); stream = null; }
  const status = await api("/api/live/stop", { method: "POST" });
  setLivePill(status);
  pushActivity("stopped");
});

el.liveClear.addEventListener("click", () => {
  liveFindings.length = 0;
  el.liveFindings.innerHTML = `<p class="hint">Cleared.</p>`;
  el.liveActivity.innerHTML = `<p class="hint">No activity yet.</p>`;
});

// ── history ─────────────────────────────────────────────────

async function loadHistory() {
  try {
    const data = await api("/api/history");
    if (!data.enabled) {
      el.historySummary.innerHTML = `<p class="hint">${esc(data.reason)}</p>`;
      return;
    }
    const s = data.summary;
    renderStats(el.historySummary, [
      { label: "Analyses", value: s.runs },
      { label: "Events seen", value: s.events_analysed },
      { label: "Findings", value: s.findings_total, cls: s.findings_total ? "warn" : "good" },
      { label: "High severity", value: s.high_total, cls: s.high_total ? "danger" : "good" },
      { label: "Distinct offenders", value: s.distinct_offenders },
      { label: "Repeat offenders", value: s.repeat_offenders, cls: s.repeat_offenders ? "warn" : "" },
      { label: "Alerts sent", value: s.alerts_sent },
    ]);

    el.repeatOffenders.innerHTML = data.repeat_offenders.length
      ? data.repeat_offenders.map((o) => `
          <div class="offender-row">
            <span class="badge ${esc(o.worst)}">${esc(o.worst)}</span>
            <div>
              <div class="key">${esc(o.key)}</div>
              <div class="detail">seen in ${plural(o.times_seen, "analysis")}${
                o.high_count ? `, ${o.high_count} high` : ""}${
                o.days_active > 0.04 ? ` · across ${o.days_active.toFixed(1)} days` : ""}</div>
            </div>
            <span class="pivot">${esc(o.pivot)}</span>
          </div>`).join("")
      : `<p class="hint">Nothing seen more than once yet. Analyse a few logs.</p>`;

    const now = Date.now() / 1000;
    el.recentRuns.innerHTML = data.runs.length
      ? data.runs.map((r) => `
          <div class="run-row">
            <span class="mode ${esc(r.mode)}">${esc(r.mode)}</span>
            <div>
              <div class="key">${esc(r.source)}</div>
              <div class="detail">${r.events} events · ${plural(r.finding_count, "finding")}${
                r.high_count ? ` · ${r.high_count} high` : ""} · ${esc(ago(now - r.started_at))}</div>
            </div>
            <span class="pivot">${r.threshold}/${r.window}s</span>
          </div>`).join("")
      : `<p class="hint">No runs recorded.</p>`;

    const alerts = await api("/api/alerts");
    el.alertLog.innerHTML = alerts.recent.length
      ? alerts.recent.map((a) => `
          <div class="run-row">
            <span class="badge ${esc(a.severity)}">${esc(a.severity)}</span>
            <div>
              <div class="key">${esc(a.key)}</div>
              <div class="detail">${esc(a.channel)} · ${a.ok ? "delivered" : esc(a.detail)} · ${esc(ago(now - a.sent_at))}</div>
            </div>
          </div>`).join("")
      : `<p class="hint">No alerts sent. Configure a channel under Setup.</p>`;
  } catch (err) {
    el.historySummary.innerHTML = `<p class="hint">${esc(err.message)}</p>`;
  }
}

el.historyRefresh.addEventListener("click", loadHistory);

el.historyClear.addEventListener("click", async () => {
  if (!window.confirm("Delete every recorded run, finding and alert? This cannot be undone.")) return;
  try {
    await api("/api/history/reset", { method: "POST" });
    loadHistory();
  } catch (err) {
    el.historySummary.innerHTML = `<p class="hint">${esc(err.message)}</p>`;
  }
});

// ── setup ───────────────────────────────────────────────────

function capabilityCard(name, ready, detail, setting) {
  return `
    <div class="capability ${ready ? "ready" : "missing"}">
      <span class="dot"></span>
      <div>
        <strong>${esc(name)}</strong>
        <small>${esc(detail)}${setting && !ready ? ` Set <code>${esc(setting)}</code>.` : ""}</small>
      </div>
      <span class="chip ${ready ? "good" : "warn"}">${ready ? "ready" : "not configured"}</span>
    </div>`;
}

async function loadSetup() {
  try {
    const data = await api("/api/config");
    const c = data.config;

    el.capabilities.innerHTML = [
      capabilityCard("Detection core", true,
        `Always on. Defaults ${data.defaults.threshold} failures / ${data.defaults.window}s.`),
      capabilityCard("Address classification", data.enrichment.classification,
        "Private / documentation / public, derived from the address itself."),
      capabilityCard("Geo + ASN lookup", data.enrichment.geo,
        data.enrichment.geo ? "MaxMind databases loaded."
          : `Inactive: ${data.enrichment.geo_error}. No locations are invented.`,
        "BFLA_GEOIP_CITY_DB and BFLA_GEOIP_ASN_DB"),
      capabilityCard("Persistence", data.persistence,
        data.persistence ? `SQLite at ${c.db_path}.` : "Disabled.", "BFLA_PERSIST"),
      capabilityCard("Allowlist", (c.allowlist || []).length > 0,
        (c.allowlist || []).length
          ? `Never alerting on: ${c.allowlist.join(", ")}.`
          : "Nothing allowlisted. You can also set it per-analysis on the Analyse tab.",
        "BFLA_ALLOWLIST"),
      capabilityCard("Live monitoring", c.watch_ready,
        c.watch_ready ? `Configured to follow ${c.watch_path}.`
          : "No default path. You can still type one on the Live tab.",
        "BFLA_WATCH_PATH"),
      capabilityCard("Alert delivery", data.alerting.enabled,
        data.alerting.enabled
          ? `${data.alerting.channels.filter((x) => x.ready).map((x) => x.name).join(", ")} · ${data.alerting.min_severity} and above.`
          : "No channel configured.",
        "BFLA_SLACK_WEBHOOK_URL, BFLA_WEBHOOK_URL or BFLA_SMTP_HOST"),
    ].join("");

    el.alertChannels.innerHTML = data.alerting.channels.map((ch) => `
      <div class="capability ${ch.ready ? "ready" : "missing"}">
        <span class="dot"></span>
        <div>
          <strong>${esc(ch.name)}</strong>
          <small>${ch.ready ? "Configured and will receive alerts."
                            : `Set ${esc(ch.missing)}`}</small>
        </div>
        <span class="chip ${ch.ready ? "good" : "warn"}">${ch.ready ? "ready" : "off"}</span>
      </div>`).join("");

    el.alertAvailability.textContent = data.alerting.enabled
      ? `Will send via ${data.alerting.channels.filter((x) => x.ready).map((x) => x.name).join(", ")} at ${data.alerting.min_severity} and above.`
      : "No alert channel configured — see the Setup tab.";
    el.sendAlerts.disabled = !data.alerting.enabled;

    el.presetHint.textContent =
      `Defaults from detector.py: ${data.defaults.threshold} failures / ${data.defaults.window}s`;

    if ((c.allowlist || []).length && !el.allowlist.value) {
      el.allowlist.value = c.allowlist.join(", ");
    }
    if (c.watch_path && !el.livePath.value) el.livePath.value = c.watch_path;
    setLivePill(data.live);
  } catch (err) {
    el.capabilities.innerHTML = `<p class="hint">${esc(err.message)}</p>`;
  }
}

async function loadBackend() {
  try {
    const b = await api("/api/backend");
    el.backend.innerHTML = `
      <h3 class="sub-h">How the detecting is actually done</h3>
      ${b.detection.map((d) => `
        <div class="capability ready">
          <span class="dot"></span>
          <div>
            <strong>${esc(d.name)}</strong>
            <small><code>${esc(d.where)}</code> — ${esc(d.detail)}</small>
          </div>
        </div>`).join("")}

      <h3 class="sub-h">Python standard library</h3>
      <table class="missing"><tbody>${b.stdlib.map(([name, use]) => `
        <tr><td><code>${esc(name)}</code></td>
            <td class="hint">${esc(use)}</td></tr>`).join("")}</tbody></table>

      <h3 class="sub-h">Outside the standard library</h3>
      ${b.third_party.map((p) => `
        <div class="capability ${p.required ? "ready" : "missing"}">
          <span class="dot"></span>
          <div>
            <strong>${esc(p.name)}</strong>
            <small>${esc(p.used_for)}${p.note ? ` — ${esc(p.note)}` : ""}</small>
          </div>
          <span class="chip ${p.required ? "good" : ""}">${p.required ? "required" : "optional"}</span>
        </div>`).join("")}

      <h3 class="sub-h">Deliberately not used</h3>
      <ul class="plain">${b.not_used.map((n) => `<li>${esc(n)}</li>`).join("")}</ul>`;
  } catch (err) {
    el.backend.innerHTML = `<p class="hint">${esc(err.message)}</p>`;
  }
}

el.setupRefresh.addEventListener("click", () => { loadSetup(); loadBackend(); });

el.alertTest.addEventListener("click", async () => {
  el.alertTest.disabled = true;
  el.alertTest.textContent = "Sending…";
  try {
    const data = await api("/api/alerts/test", { method: "POST" });
    el.alertTestResult.hidden = false;
    el.alertTestResult.innerHTML = data.results
      .map((r) => `${esc(r.channel)}: ${r.ok ? "delivered" : esc(r.reason)}`).join("<br>");
  } catch (err) {
    el.alertTestResult.hidden = false;
    el.alertTestResult.innerHTML = esc(err.message);
  } finally {
    el.alertTest.disabled = false;
    el.alertTest.textContent = "Send test alert";
  }
});

// ── theme ───────────────────────────────────────────────────

const root = document.documentElement;
const saved = localStorage.getItem("bfla-theme");
if (saved) root.dataset.theme = saved;
const syncThemeLabel = () => {
  el.theme.textContent = root.dataset.theme === "light" ? "Dark" : "Light";
};
syncThemeLabel();
el.theme.addEventListener("click", () => {
  root.dataset.theme = root.dataset.theme === "light" ? "dark" : "light";
  localStorage.setItem("bfla-theme", root.dataset.theme);
  syncThemeLabel();
});

// ── boot ────────────────────────────────────────────────────

updateLineCount();
loadSamples();
loadSetup();
refreshLiveStatus();
