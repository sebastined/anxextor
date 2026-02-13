const form = document.getElementById("scan-form");
const statusEl = document.getElementById("status");
const resultsSection = document.getElementById("results");
const scoreEl = document.getElementById("score");
const gradeEl = document.getElementById("grade");
const timingEl = document.getElementById("timing");
const findingsEl = document.getElementById("findings");
const tlsEl = document.getElementById("tls");
const dnsEl = document.getElementById("dns");
const scoreFillEl = document.getElementById("score-fill");
const highCountEl = document.getElementById("high-count");
const mediumCountEl = document.getElementById("medium-count");
const lowCountEl = document.getElementById("low-count");
const infoCountEl = document.getElementById("info-count");
const historyEl = document.getElementById("history");
const copyBtn = document.getElementById("copy-json");
const downloadBtn = document.getElementById("download-json");
const csvBtn = document.getElementById("download-csv");
const pdfBtn = document.getElementById("download-pdf");
const remediationEl = document.getElementById("remediation");
const themeToggle = document.getElementById("theme-toggle");
const targetListEl = document.getElementById("target-list");
const addTargetBtn = document.getElementById("add-target");
const batchResultsEl = document.getElementById("batch-results");
const visitorSection = document.getElementById("visitor");
const visitorProfileEl = document.getElementById("visitor-profile");
const visitorWindowsEl = document.getElementById("visitor-windows");
const feedbackUpBtn = document.getElementById("feedback-up");
const feedbackDownBtn = document.getElementById("feedback-down");
const feedbackUpCountEl = document.getElementById("feedback-up-count");
const feedbackDownCountEl = document.getElementById("feedback-down-count");
const feedbackModal = document.getElementById("feedback-modal");
const feedbackModalUp = document.getElementById("feedback-modal-up");
const feedbackModalDown = document.getElementById("feedback-modal-down");
const feedbackModalClose = document.getElementById("feedback-modal-close");

const THEME_KEY = "anxextor.theme";
const FEEDBACK_KEY = "anxextor.feedback";
const FEEDBACK_DISMISS_KEY = "anxextor.feedback.dismissed";
const FEEDBACK_POPUP_DELAY_MS = 60000;
let lastResult = null;
let lastBatch = [];
let fingerprintId = "";
const historyEntries = [];

const sanitizeText = (value) => {
  if (typeof DOMPurify !== "undefined") {
    return DOMPurify.sanitize(String(value ?? ""), {
      ALLOWED_TAGS: [],
      ALLOWED_ATTR: [],
    }).trim();
  }
  return String(value ?? "").replace(/[<>]/g, "").trim();
};

const sanitizeFinding = (finding) => ({
  id: sanitizeText(finding.id),
  title: sanitizeText(finding.title),
  severity: sanitizeText(finding.severity),
  description: sanitizeText(finding.description),
  recommendation: sanitizeText(finding.recommendation),
});

const sanitizeResult = (data) => ({
  target: sanitizeText(data.target),
  final_url: sanitizeText(data.final_url),
  status_code: Number(data.status_code ?? 0),
  score: Number(data.score ?? 0),
  grade: sanitizeText(data.grade),
  findings: Array.isArray(data.findings)
    ? data.findings.map(sanitizeFinding)
    : [],
  headers: data.headers || {},
  tls: data.tls || null,
  dns: data.dns || {},
  timing_ms: Number(data.timing_ms ?? 0),
});

const loadFingerprintModule = async (publicKey) => {
  const url = `https://fpjscdn.net/v3/${encodeURIComponent(publicKey)}`;
  const module = await import(url);
  if (module && typeof module.load === "function") {
    return module.load;
  }
  if (module && module.default) {
    if (typeof module.default.load === "function") {
      return module.default.load;
    }
    if (typeof module.default === "function") {
      return module.default;
    }
  }
  return null;
};

const fetchConfig = async () => {
  try {
    const response = await fetch("/api/config");
    if (!response.ok) {
      return null;
    }
    return await response.json();
  } catch (error) {
    return null;
  }
};

const renderVisitor = (snapshot) => {
  if (!snapshot) {
    return;
  }
  const safeSnapshot = {
    fingerprint_id: sanitizeText(snapshot.fingerprint_id),
    ip: sanitizeText(snapshot.ip),
    country: sanitizeText(snapshot.country || "n/a"),
    city: sanitizeText(snapshot.city || "n/a"),
    behind_proxy: sanitizeText(
      snapshot.behind_proxy === null || snapshot.behind_proxy === undefined
        ? "n/a"
        : snapshot.behind_proxy
        ? "yes"
        : "no"
    ),
    visit_count: sanitizeText(snapshot.visit_count),
    scan_count: sanitizeText(snapshot.scan_count),
    last_visit_at: sanitizeText(snapshot.last_visit_at),
  };

  renderKeyValue(visitorProfileEl, {
    "Fingerprint ID": safeSnapshot.fingerprint_id,
    "Source IP": safeSnapshot.ip,
    Country: safeSnapshot.country,
    City: safeSnapshot.city,
    "Proxy/VPN": safeSnapshot.behind_proxy,
    "Visits": safeSnapshot.visit_count,
    "Scans": safeSnapshot.scan_count,
    "Last visit": safeSnapshot.last_visit_at,
  });

  const windows = snapshot.visit_windows || {};
  renderKeyValue(visitorWindowsEl, {
    "5 min": windows["5m"] ?? 0,
    "30 min": windows["30m"] ?? 0,
    "1 hour": windows["1h"] ?? 0,
    "1 day": windows["1d"] ?? 0,
    "1 week": windows["1w"] ?? 0,
    "1 month": windows["1mo"] ?? 0,
    "1 year": windows["1y"] ?? 0,
  });

  visitorSection.hidden = false;
};

const initFingerprint = async () => {
  const config = await fetchConfig();
  if (!config || !config.visitor_tracking_enabled) {
    return "";
  }
  const publicKey = sanitizeText(config.fingerprint_public_key || "");
  if (!publicKey) {
    return "";
  }
  const region = sanitizeText(config.fingerprint_region || "").toLowerCase();
  try {
    const loadFingerprint = await loadFingerprintModule(publicKey);
    if (!loadFingerprint) {
      return "";
    }
    const loadOptions = { token: publicKey };
    if (region === "eu" || region === "ap" || region === "us") {
      loadOptions.region = region;
    }
    const fp = await loadFingerprint(loadOptions);
    const result = await fp.get();
    fingerprintId = sanitizeText(result.visitorId || "");
    return fingerprintId;
  } catch (error) {
    return "";
  }
};

const registerVisitor = async () => {
  if (!fingerprintId) {
    return;
  }
  try {
    const response = await fetch("/api/visitor", {
      method: "POST",
      headers: { "X-Fingerprint-ID": fingerprintId },
    });
    if (!response.ok) {
      return;
    }
    const data = await response.json();
    if (data && data.enabled) {
      renderVisitor(data.snapshot);
    }
  } catch (error) {
    return;
  }
};

const getFeedbackFingerprint = () => {
  if (fingerprintId) {
    return fingerprintId;
  }
  const cached = localStorage.getItem("anxextor.fallback_fp");
  if (cached) {
    return cached;
  }
  const fallback =
    typeof crypto !== "undefined" && crypto.randomUUID
      ? crypto.randomUUID()
      : `fallback-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  localStorage.setItem("anxextor.fallback_fp", fallback);
  return fallback;
};

const setFeedbackActive = (rating) => {
  if (feedbackUpBtn) {
    feedbackUpBtn.classList.toggle("active", rating === "up");
  }
  if (feedbackDownBtn) {
    feedbackDownBtn.classList.toggle("active", rating === "down");
  }
};

const hideFeedbackModal = () => {
  if (feedbackModal) {
    feedbackModal.hidden = true;
  }
};

const setFeedbackCounts = (summary) => {
  if (!summary) {
    return;
  }
  const up = Number(summary.up ?? 0);
  const down = Number(summary.down ?? 0);
  if (feedbackUpCountEl) {
    feedbackUpCountEl.textContent = String(up);
  }
  if (feedbackDownCountEl) {
    feedbackDownCountEl.textContent = String(down);
  }
  if (summary.user_rating) {
    setFeedbackActive(summary.user_rating);
  }
};

const fetchFeedbackSummary = async () => {
  const fingerprint = getFeedbackFingerprint();
  try {
    const response = await fetch(
      `/api/feedback/summary?page=${encodeURIComponent(window.location.pathname)}`,
      {
        headers: { "X-Fingerprint-ID": fingerprint },
      }
    );
    if (!response.ok) {
      return;
    }
    const data = await response.json();
    setFeedbackCounts(data.summary);
  } catch (error) {
    return;
  }
};

const submitFeedback = async (rating) => {
  if (rating !== "up" && rating !== "down") {
    return;
  }
  const existing = localStorage.getItem(FEEDBACK_KEY);
  if (existing) {
    setFeedbackActive(existing);
    hideFeedbackModal();
    return;
  }

  localStorage.setItem(FEEDBACK_KEY, rating);
  setFeedbackActive(rating);
  hideFeedbackModal();

  const fingerprint = getFeedbackFingerprint();
  try {
    const response = await fetch("/api/feedback", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Fingerprint-ID": fingerprint,
      },
      body: JSON.stringify({ rating, page: window.location.pathname }),
    });
    if (!response.ok) {
      return;
    }
    const data = await response.json();
    setFeedbackCounts(data.summary);
  } catch (error) {
    return;
  }
};

const scheduleFeedbackPopup = () => {
  const existing = localStorage.getItem(FEEDBACK_KEY);
  const dismissed = sessionStorage.getItem(FEEDBACK_DISMISS_KEY);
  if (existing || dismissed) {
    return;
  }
  setTimeout(() => {
    if (!localStorage.getItem(FEEDBACK_KEY) && feedbackModal) {
      feedbackModal.hidden = false;
    }
  }, FEEDBACK_POPUP_DELAY_MS);
};

const renderKeyValue = (target, data) => {
  target.innerHTML = "";
  Object.entries(data || {}).forEach(([key, value]) => {
    const row = document.createElement("div");
    const label = document.createElement("span");
    const val = document.createElement("span");

    label.textContent = `${sanitizeText(key)}: `;
    val.textContent = sanitizeText(value ?? "n/a");

    row.appendChild(label);
    row.appendChild(val);
    target.appendChild(row);
  });
};

const renderFindings = (items) => {
  findingsEl.innerHTML = "";
  items.forEach((finding) => {
    const li = document.createElement("li");
    const title = document.createElement("strong");
    const description = document.createElement("small");
    const recommendation = document.createElement("em");

    li.classList.add(sanitizeText(finding.severity));
    title.textContent = sanitizeText(finding.title);
    description.textContent = sanitizeText(finding.description);
    recommendation.textContent = sanitizeText(finding.recommendation);

    li.appendChild(title);
    li.appendChild(document.createElement("br"));
    li.appendChild(description);
    li.appendChild(document.createElement("br"));
    li.appendChild(recommendation);

    findingsEl.appendChild(li);
  });
};

const renderSummary = (findings) => {
  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((finding) => {
    const severity = sanitizeText(finding.severity);
    if (counts[severity] !== undefined) {
      counts[severity] += 1;
    }
  });

  highCountEl.textContent = counts.high;
  mediumCountEl.textContent = counts.medium;
  lowCountEl.textContent = counts.low;
  infoCountEl.textContent = counts.info;
};

const renderRemediation = (findings) => {
  remediationEl.innerHTML = "";
  const seen = new Set();
  findings.forEach((finding) => {
    const recommendation = sanitizeText(finding.recommendation);
    if (!recommendation || seen.has(recommendation)) {
      return;
    }
    seen.add(recommendation);
    const li = document.createElement("li");
    li.textContent = recommendation;
    remediationEl.appendChild(li);
  });
  if (!remediationEl.children.length) {
    const li = document.createElement("li");
    li.textContent = "No remediation steps needed.";
    remediationEl.appendChild(li);
  }
};

const renderHistory = () => {
  historyEl.innerHTML = "";
  historyEntries.forEach((entry) => {
    const li = document.createElement("li");

    const host = sanitizeText(entry.host);
    const timestamp = sanitizeText(entry.timestamp);

    li.textContent = `${host} (${timestamp})`;
    li.addEventListener("click", () => {
      const targetInput = document.querySelector(".target-input");
      targetInput.value = host;
      form.requestSubmit();
    });
    historyEl.appendChild(li);
  });
};

const renderBatchResults = (results) => {
  batchResultsEl.innerHTML = "";
  results.forEach((result) => {
    const safeResult = sanitizeResult(result);
    const li = document.createElement("li");

    const grade = sanitizeText(safeResult.grade);
    const finalUrl = sanitizeText(safeResult.final_url);
    li.textContent = `${grade} ${safeResult.score} - ${finalUrl} (Findings: ${safeResult.findings.length})`;
    li.addEventListener("click", () => renderResult(safeResult, false));
    batchResultsEl.appendChild(li);
  });
};

const saveHistory = (data) => {
  const safeData = sanitizeResult(data);
  const host = new URL(safeData.final_url).host;
  historyEntries.unshift({
    host,
    timestamp: new Date().toLocaleString(),
  });
  historyEntries.splice(6);
  renderHistory();
};

const renderResult = (data, save = true) => {
  const safeData = sanitizeResult(data);
  lastResult = safeData;
  scoreEl.textContent = String(safeData.score);
  gradeEl.textContent = sanitizeText(safeData.grade);
  timingEl.textContent = `Completed in ${sanitizeText(safeData.timing_ms)} ms`;
  scoreFillEl.style.width = `${safeData.score}%`;

  renderFindings(safeData.findings);
  renderSummary(safeData.findings);
  renderRemediation(safeData.findings);
  renderKeyValue(tlsEl, safeData.tls || { status: "Not available" });
  renderKeyValue(dnsEl, safeData.dns || {});

  resultsSection.hidden = false;
  statusEl.textContent = `Scan complete for ${sanitizeText(safeData.final_url)}`;

  if (save) {
    saveHistory(safeData);
  }
};

const addTargetRow = (value = "") => {
  const row = document.createElement("div");
  row.className = "target-row";

  const input = document.createElement("input");
  input.className = "target-input";
  input.type = "text";
  input.placeholder = "example.com or https://example.com";
  input.value = value;
  input.required = true;

  const removeBtn = document.createElement("button");
  removeBtn.className = "remove-target btn-3d";
  removeBtn.type = "button";
  removeBtn.textContent = "Remove";
  removeBtn.addEventListener("click", () => {
    row.remove();
    updateRemoveButtons();
  });

  row.appendChild(input);
  row.appendChild(removeBtn);
  targetListEl.appendChild(row);
  updateRemoveButtons();
};

const updateRemoveButtons = () => {
  const rows = targetListEl.querySelectorAll(".target-row");
  rows.forEach((row, index) => {
    const removeBtn = row.querySelector(".remove-target");
    removeBtn.hidden = rows.length === 1;
  });
};

addTargetBtn.addEventListener("click", () => addTargetRow());

copyBtn.addEventListener("click", async () => {
  if (!lastResult) {
    return;
  }
  try {
    await navigator.clipboard.writeText(JSON.stringify(lastResult, null, 2));
    statusEl.textContent = "JSON copied to clipboard.";
  } catch (error) {
    statusEl.textContent = "Copy failed.";
  }
});

downloadBtn.addEventListener("click", () => {
  if (!lastResult) {
    return;
  }
  const safeResult = sanitizeResult(lastResult);
  const blob = new Blob([JSON.stringify(safeResult, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const safeUrl = sanitizeText(url);
  if (!safeUrl.startsWith("blob:")) {
    URL.revokeObjectURL(url);
    return;
  }
  const link = document.createElement("a");
  link.href = safeUrl;
  link.download = "scan-result.json";
  link.click();
  URL.revokeObjectURL(url);
});

csvBtn.addEventListener("click", () => {
  if (!lastResult) {
    return;
  }
  const safeResult = sanitizeResult(lastResult);
  const rows = [
    ["id", "title", "severity", "description", "recommendation"],
    ...safeResult.findings.map((finding) => [
      sanitizeText(finding.id),
      sanitizeText(finding.title),
      sanitizeText(finding.severity),
      sanitizeText(finding.description),
      sanitizeText(finding.recommendation),
    ]),
  ];

  const csv = rows
    .map((row) =>
      row
        .map((value) => `"${String(value ?? "").replace(/"/g, '""')}"`)
        .join(",")
    )
    .join("\n");

  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const safeUrl = sanitizeText(url);
  if (!safeUrl.startsWith("blob:")) {
    URL.revokeObjectURL(url);
    return;
  }
  const link = document.createElement("a");
  link.href = safeUrl;
  link.download = "scan-findings.csv";
  link.click();
  URL.revokeObjectURL(url);
});

pdfBtn.addEventListener("click", () => {
  if (!lastResult) {
    return;
  }
  const safeResult = sanitizeResult(lastResult);
  const printWindow = window.open("", "_blank");
  if (!printWindow) {
    statusEl.textContent = "Popup blocked. Allow popups to export PDF.";
    return;
  }

  const doc = printWindow.document;
  doc.title = "anxextor scan report";
  const body = doc.body;

  const heading = doc.createElement("h1");
  heading.textContent = "anxextor scan report";
  body.appendChild(heading);

  const meta = doc.createElement("p");
  meta.textContent = `Target: ${sanitizeText(safeResult.final_url)} | Score: ${safeResult.score} | Grade: ${sanitizeText(safeResult.grade)}`;
  body.appendChild(meta);

  const listTitle = doc.createElement("h2");
  listTitle.textContent = "Findings";
  body.appendChild(listTitle);

  const list = doc.createElement("ol");
  safeResult.findings.forEach((finding) => {
    const li = doc.createElement("li");
    const severity = sanitizeText(finding.severity).toUpperCase();
    const title = sanitizeText(finding.title);
    const rec = sanitizeText(finding.recommendation);
    li.textContent = `${severity}: ${title} - ${rec}`;
    list.appendChild(li);
  });
  body.appendChild(list);

  const remediationTitle = doc.createElement("h2");
  remediationTitle.textContent = "Remediation";
  body.appendChild(remediationTitle);

  const remList = doc.createElement("ol");
  remediationEl.childNodes.forEach((node) => {
    const li = doc.createElement("li");
    li.textContent = sanitizeText(node.textContent || "");
    remList.appendChild(li);
  });
  body.appendChild(remList);

  doc.close();
  printWindow.focus();
  printWindow.print();
});

const setTheme = (theme) => {
  document.documentElement.setAttribute("data-theme", theme);
  themeToggle.textContent = theme === "light" ? "Dark mode" : "Light mode";
  localStorage.setItem(THEME_KEY, theme);
};

themeToggle.addEventListener("click", () => {
  const current = localStorage.getItem(THEME_KEY) || "dark";
  setTheme(current === "dark" ? "light" : "dark");
});

if (feedbackUpBtn) {
  feedbackUpBtn.addEventListener("click", () => submitFeedback("up"));
}

if (feedbackDownBtn) {
  feedbackDownBtn.addEventListener("click", () => submitFeedback("down"));
}

if (feedbackModalUp) {
  feedbackModalUp.addEventListener("click", () => {
    sessionStorage.setItem(FEEDBACK_DISMISS_KEY, "1");
    hideFeedbackModal();
    submitFeedback("up");
  });
}

if (feedbackModalDown) {
  feedbackModalDown.addEventListener("click", () => {
    sessionStorage.setItem(FEEDBACK_DISMISS_KEY, "1");
    hideFeedbackModal();
    submitFeedback("down");
  });
}

if (feedbackModalClose) {
  feedbackModalClose.addEventListener("click", () => {
    sessionStorage.setItem(FEEDBACK_DISMISS_KEY, "1");
    hideFeedbackModal();
  });
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  statusEl.textContent = "Scanning...";
  resultsSection.hidden = true;

  const targets = Array.from(document.querySelectorAll(".target-input"))
    .map((input) => input.value.trim())
    .filter(Boolean);
  const url = targets[0] || "";
  try {
    const headers = { "Content-Type": "application/json" };
    if (fingerprintId) {
      headers["X-Fingerprint-ID"] = fingerprintId;
    }

    const endpoint = targets.length > 1 ? "/api/scan/batch" : "/api/scan";
    const payload = targets.length > 1 ? { targets } : { url };

    const response = await fetch(endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(sanitizeText(error.detail || "Scan failed"));
    }

    const data = await response.json();
    if (targets.length > 1) {
      lastBatch = (data.results || []).map((result) => sanitizeResult(result));
      renderBatchResults(lastBatch);
      if (lastBatch.length) {
        renderResult(lastBatch[0], true);
      }
      if (data.errors && data.errors.length) {
        statusEl.textContent = `Batch completed with ${data.errors.length} errors.`;
      }
    } else {
      renderResult(data, true);
    }
  } catch (error) {
    statusEl.textContent = sanitizeText(error.message);
  }
});

const bootstrap = async () => {
  await initFingerprint();
  await registerVisitor();
  const existing = localStorage.getItem(FEEDBACK_KEY);
  if (existing) {
    setFeedbackActive(existing);
  }
  await fetchFeedbackSummary();
  scheduleFeedbackPopup();
};

bootstrap();
renderHistory();
setTheme(localStorage.getItem(THEME_KEY) || "dark");
updateRemoveButtons();
const yearEl = document.getElementById("year");
if (yearEl) {
  yearEl.textContent = String(new Date().getFullYear());
}
