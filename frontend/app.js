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
  cve: finding.cve ? sanitizeText(finding.cve) : null,
  cvss_score: finding.cvss_score ? Number(finding.cvss_score) : null,
  reference_url: finding.reference_url ? sanitizeText(finding.reference_url) : null,
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

  // Update UI immediately
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
    
    // Add CVE/CVSS badge if available
    if (finding.cve || finding.cvss_score) {
      const badge = document.createElement("span");
      badge.style.cssText = "font-size: 11px; margin-left: 8px; padding: 2px 6px; background: #333; color: #fff; border-radius: 3px; font-family: monospace;";
      let badgeText = "";
      if (finding.cve) {
        badgeText = sanitizeText(finding.cve);
      }
      if (finding.cvss_score) {
        badgeText += (badgeText ? " | " : "") + `CVSS: ${finding.cvss_score}`;
      }
      badge.textContent = badgeText;
      title.appendChild(badge);
    }
    
    description.textContent = sanitizeText(finding.description);
    recommendation.textContent = sanitizeText(finding.recommendation);

    li.appendChild(title);
    li.appendChild(document.createElement("br"));
    li.appendChild(description);
    li.appendChild(document.createElement("br"));
    li.appendChild(recommendation);
    
    // Add reference link if available
    if (finding.reference_url) {
      const refLink = document.createElement("a");
      refLink.href = sanitizeText(finding.reference_url);
      refLink.target = "_blank";
      refLink.rel = "noopener noreferrer";
      refLink.textContent = " Learn more »";
      refLink.style.cssText = "color: #0066cc; text-decoration: none; font-size: 12px; margin-left: 5px;";
      li.appendChild(refLink);
    }

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
    const reportData = {
      ...lastResult,
      report_metadata: {
        generated_at: new Date().toISOString(),
        generated_by: "anxextor Security Scanner",
        consultant_contact: "iam@sebastine.com",
      },
    };
    await navigator.clipboard.writeText(JSON.stringify(reportData, null, 2));
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
  const reportData = {
    ...safeResult,
    report_metadata: {
      generated_at: new Date().toISOString(),
      generated_by: "anxextor Security Scanner",
      consultant_contact: "iam@sebastine.com",
    },
  };
  const blob = new Blob([JSON.stringify(reportData, null, 2)], {
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
    ["id", "title", "severity", "cve", "cvss_score", "description", "recommendation", "reference_url"],
    ...safeResult.findings.map((finding) => [
      sanitizeText(finding.id),
      sanitizeText(finding.title),
      sanitizeText(finding.severity),
      sanitizeText(finding.cve || "N/A"),
      sanitizeText(finding.cvss_score || "N/A"),
      sanitizeText(finding.description),
      sanitizeText(finding.recommendation),
      sanitizeText(finding.reference_url || "N/A"),
    ]),
    [],
    ["Report Metadata"],
    ["Generated At", new Date().toISOString()],
    ["Target", sanitizeText(safeResult.final_url)],
    ["Score", safeResult.score],
    ["Grade", sanitizeText(safeResult.grade)],
    [],
    ["For security consultation, contact: iam@sebastine.com"],
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
  doc.title = "anxextor Security Assessment Report";
  const body = doc.body;

  // Add professional OWASP-style styling
  const style = doc.createElement("style");
  style.textContent = `
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Calibri', 'Segoe UI', Arial, sans-serif; font-size: 11pt; color: #1f1f1f; line-height: 1.5; background: white; }
    
    /* Page breaks */
    .page-break { page-break-after: always; margin-bottom: 40px; }
    
    /* Header & Title */
    .header { background: linear-gradient(135deg, #1a237e 0%, #283593 100%); color: white; padding: 40px; text-align: center; margin-bottom: 40px; }
    .header h1 { font-size: 28pt; font-weight: bold; margin-bottom: 10px; }
    .header .subtitle { font-size: 12pt; opacity: 0.9; }
    
    /* Executive Summary */
    .executive-summary { background: #f5f5f5; border-left: 5px solid #1976d2; padding: 20px; margin-bottom: 30px; }
    .executive-summary h2 { font-size: 14pt; font-weight: bold; margin-bottom: 15px; color: #1a237e; }
    .summary-item { margin-bottom: 10px; }
    .summary-item strong { color: #1f1f1f; }
    
    /* Score/Risk Section */
    .risk-overview { display: table; width: 100%; margin-bottom: 30px; border-collapse: collapse; }
    .risk-cell { display: table-cell; border: 1px solid #ddd; padding: 15px; }
    .risk-label { font-weight: bold; color: #1a237e; }
    .risk-value { font-size: 18pt; font-weight: bold; margin-top: 5px; }
    .risk-critical { color: #d32f2f; }
    .risk-high { color: #f57c00; }
    .risk-medium { color: #fbc02d; }
    .risk-low { color: #388e3c; }
    
    /* Table of Contents */
    .toc { page-break-after: always; margin-bottom: 40px; }
    .toc h2 { font-size: 14pt; font-weight: bold; margin-bottom: 15px; color: #1a237e; border-bottom: 2px solid #1976d2; padding-bottom: 10px; }
    .toc-item { margin-bottom: 8px; padding-left: 20px; }
    .toc-item::before { content: "• "; color: #1976d2; }
    
    /* Severity Breakdown */
    .severity-breakdown { margin-bottom: 30px; }
    .severity-breakdown h2 { font-size: 14pt; font-weight: bold; margin-bottom: 15px; color: #1a237e; }
    .severity-chart { display: table; width: 100%; border-collapse: collapse; }
    .severity-row { display: table-row; }
    .severity-cell { display: table-cell; padding: 10px; border: 1px solid #e0e0e0; text-align: center; }
    .severity-cell-label { font-weight: bold; }
    .severity-cell-critical { background: #ffebee; color: #d32f2f; font-weight: bold; }
    .severity-cell-high { background: #fff3e0; color: #f57c00; font-weight: bold; }
    .severity-cell-medium { background: #fffde7; color: #fbc02d; font-weight: bold; }
    .severity-cell-low { background: #e8f5e9; color: #388e3c; font-weight: bold; }
    
    /* Findings Section */
    .findings-section { page-break-before: always; margin-top: 40px; margin-bottom: 40px; }
    .findings-section h2 { font-size: 14pt; font-weight: bold; margin-bottom: 20px; color: #1a237e; border-bottom: 2px solid #1976d2; padding-bottom: 10px; }
    .findings-list { list-style: none; }
    .finding-item { margin-bottom: 30px; page-break-inside: avoid; border: 1px solid #e0e0e0; padding: 15px; background: #fafafa; }
    
    /* Finding Header */
    .finding-header { display: table; width: 100%; margin-bottom: 10px; border-bottom: 1px solid #e0e0e0; padding-bottom: 10px; }
    .finding-number { display: table-cell; font-weight: bold; color: #1976d2; vertical-align: top; width: 40px; }
    .finding-title-cell { display: table-cell; vertical-align: top; padding-left: 10px; }
    .finding-title { font-weight: bold; font-size: 12pt; color: #1f1f1f; margin-bottom: 5px; }
    .finding-badges { display: inline-block; }
    .finding-badges .badge { display: inline-block; margin-right: 10px; padding: 3px 8px; border-radius: 3px; font-size: 9pt; font-weight: bold; }
    .badge-severity { background: #f5f5f5; border: 1px solid #999; }
    .badge-critical { background: #d32f2f; color: white; }
    .badge-high { background: #f57c00; color: white; }
    .badge-medium { background: #fbc02d; color: #1f1f1f; }
    .badge-low { background: #388e3c; color: white; }
    .badge-cve { background: #1976d2; color: white; }
    .badge-cvss { background: #424242; color: white; }
    
    /* Finding Content */
    .finding-content { margin-top: 10px; }
    .finding-detail { margin-bottom: 8px; }
    .finding-detail-label { font-weight: bold; color: #1a237e; display: inline-block; width: 120px; }
    .finding-detail-value { color: #1f1f1f; }
    
    /* Remediation */
    .remediation-box { background: #e3f2fd; border-left: 4px solid #1976d2; padding: 12px; margin-top: 10px; }
    .remediation-label { font-weight: bold; color: #1a237e; margin-bottom: 5px; }
    .remediation-text { color: #1f1f1f; font-size: 10pt; line-height: 1.4; }
    
    /* Reference */
    .reference-link { color: #1976d2; text-decoration: none; font-family: monospace; font-size: 9pt; }
    
    /* Metadata Footer */
    .metadata { margin-top: 40px; padding: 15px; background: #f5f5f5; border: 1px solid #ddd; font-size: 9pt; color: #666; }
    .metadata p { margin-bottom: 8px; }
    .consultant { background: #e3f2fd; padding: 15px; border-left: 4px solid #1976d2; margin-top: 20px; text-align: center; }
    .consultant-label { font-weight: bold; color: #1a237e; }
    .consultant-email { font-size: 12pt; font-weight: bold; color: #1976d2; margin-top: 5px; }
    
    /* Print optimizations */
    @media print {
      body { margin: 0; padding: 0; }
      .page-break { page-break-after: always; }
      .finding-item { page-break-inside: avoid; }
      .findings-section { page-break-before: always; }
    }
  `;
  doc.head.appendChild(style);

  // == COVER PAGE ==
  // Header
  const header = doc.createElement("div");
  header.className = "header";
  const heading = doc.createElement("h1");
  heading.textContent = "Security Assessment Report";
  header.appendChild(heading);
  const subtitle = doc.createElement("div");
  subtitle.className = "subtitle";
  subtitle.textContent = "Web Security Scanner Assessment";
  header.appendChild(subtitle);
  body.appendChild(header);

  // Executive Summary
  const execSummary = doc.createElement("div");
  execSummary.className = "executive-summary";
  const execTitle = doc.createElement("h2");
  execTitle.textContent = "Executive Summary";
  execSummary.appendChild(execTitle);
  
  const criticalCount = safeResult.findings.filter(f => f.severity === "Critical").length;
  const highCount = safeResult.findings.filter(f => f.severity === "High").length;
  const mediumCount = safeResult.findings.filter(f => f.severity === "Medium").length;
  const lowCount = safeResult.findings.filter(f => f.severity === "Low").length;
  
  const summaryItems = [
    { label: "Assessment Target", value: sanitizeText(safeResult.final_url) },
    { label: "Assessment Date", value: new Date().toLocaleString() },
    { label: "Overall Risk Rating", value: `Grade: ${sanitizeText(safeResult.grade)} (${safeResult.score}/100)` },
    { label: "Critical Issues", value: `${criticalCount}` },
    { label: "High Issues", value: `${highCount}` },
    { label: "Medium Issues", value: `${mediumCount}` },
    { label: "Low Issues", value: `${lowCount}` },
    { label: "Total Findings", value: `${safeResult.findings.length}` },
  ];
  
  summaryItems.forEach(item => {
    const itemDiv = doc.createElement("div");
    itemDiv.className = "summary-item";
    itemDiv.innerHTML = `<strong>${item.label}:</strong> ${item.value}`;
    execSummary.appendChild(itemDiv);
  });
  body.appendChild(execSummary);

  // Risk Overview
  const riskOverview = doc.createElement("div");
  const riskTitle = doc.createElement("h2");
  riskTitle.textContent = "Risk Overview";
  riskTitle.style.marginBottom = "15px";
  riskTitle.style.borderBottom = "2px solid #1976d2";
  riskTitle.style.paddingBottom = "10px";
  riskTitle.style.color = "#1a237e";
  riskOverview.appendChild(riskTitle);
  
  const riskTable = doc.createElement("div");
  riskTable.className = "risk-overview";
  const severityCounts = [
    { level: "Critical", count: criticalCount, class: "risk-critical" },
    { level: "High", count: highCount, class: "risk-high" },
    { level: "Medium", count: mediumCount, class: "risk-medium" },
    { level: "Low", count: lowCount, class: "risk-low" },
  ];
  
  severityCounts.forEach(item => {
    const cell = doc.createElement("div");
    cell.className = "risk-cell";
    const label = doc.createElement("div");
    label.className = "risk-label";
    label.textContent = item.level;
    const value = doc.createElement("div");
    value.className = `risk-value ${item.class}`;
    value.textContent = item.count;
    cell.appendChild(label);
    cell.appendChild(value);
    riskTable.appendChild(cell);
  });
  riskOverview.appendChild(riskTable);
  body.appendChild(riskOverview);

  // Page break before findings
  const pageBreak = doc.createElement("div");
  pageBreak.className = "page-break";
  body.appendChild(pageBreak);

  // == FINDINGS SECTION ==
  const findingsSection = doc.createElement("div");
  findingsSection.className = "findings-section";
  const findingsTitle = doc.createElement("h2");
  findingsTitle.textContent = `Detailed Security Findings (${safeResult.findings.length})`;
  findingsSection.appendChild(findingsTitle);
  
  const findingsList = doc.createElement("ul");
  findingsList.className = "findings-list";
  
  safeResult.findings.forEach((finding, index) => {
    const findingItem = doc.createElement("li");
    findingItem.className = "finding-item";
    
    // Finding Header with number and title
    const header = doc.createElement("div");
    header.className = "finding-header";
    
    const number = doc.createElement("div");
    number.className = "finding-number";
    number.textContent = `${index + 1}.`;
    header.appendChild(number);
    
    const titleCell = doc.createElement("div");
    titleCell.className = "finding-title-cell";
    
    const title = doc.createElement("div");
    title.className = "finding-title";
    title.textContent = sanitizeText(finding.title);
    titleCell.appendChild(title);
    
    // Badges
    const badges = doc.createElement("div");
    badges.className = "finding-badges";
    
    const severityBadge = doc.createElement("span");
    severityBadge.className = `badge badge-${sanitizeText(finding.severity).toLowerCase()}`;
    severityBadge.textContent = sanitizeText(finding.severity).toUpperCase();
    badges.appendChild(severityBadge);
    
    if (finding.cve) {
      const cveBadge = doc.createElement("span");
      cveBadge.className = "badge badge-cve";
      cveBadge.textContent = sanitizeText(finding.cve);
      badges.appendChild(cveBadge);
    }
    
    if (finding.cvss_score) {
      const cvssBadge = doc.createElement("span");
      cvssBadge.className = "badge badge-cvss";
      cvssBadge.textContent = `CVSS: ${finding.cvss_score}`;
      badges.appendChild(cvssBadge);
    }
    
    titleCell.appendChild(badges);
    header.appendChild(titleCell);
    findingItem.appendChild(header);
    
    // Finding Content
    const content = doc.createElement("div");
    content.className = "finding-content";
    
    const descDetail = doc.createElement("div");
    descDetail.className = "finding-detail";
    descDetail.innerHTML = `<span class="finding-detail-label">Description:</span> <span class="finding-detail-value">${sanitizeText(finding.description)}</span>`;
    content.appendChild(descDetail);
    
    if (finding.cve && finding.reference_url) {
      const refDetail = doc.createElement("div");
      refDetail.className = "finding-detail";
      refDetail.innerHTML = `<span class="finding-detail-label">Reference:</span> <span class="finding-detail-value"><a class="reference-link" href="${sanitizeText(finding.reference_url)}" target="_blank">${sanitizeText(finding.reference_url)}</a></span>`;
      content.appendChild(refDetail);
    }
    
    // Remediation Box
    const remediationBox = doc.createElement("div");
    remediationBox.className = "remediation-box";
    const remLabel = doc.createElement("div");
    remLabel.className = "remediation-label";
    remLabel.textContent = "Recommended Remediation:";
    remediationBox.appendChild(remLabel);
    const remText = doc.createElement("div");
    remText.className = "remediation-text";
    remText.textContent = sanitizeText(finding.recommendation);
    remediationBox.appendChild(remText);
    content.appendChild(remediationBox);
    
    findingItem.appendChild(content);
    findingsList.appendChild(findingItem);
  });
  
  findingsSection.appendChild(findingsList);
  body.appendChild(findingsSection);

  // Page break before metadata
  const pageBreak2 = doc.createElement("div");
  pageBreak2.className = "page-break";
  body.appendChild(pageBreak2);

  // Metadata Footer
  const metadata = doc.createElement("div");
  metadata.className = "metadata";
  
  const metaItems = [
    { label: "Target URL", value: sanitizeText(safeResult.final_url) },
    { label: "Report Generated", value: new Date().toLocaleString() },
    { label: "Scanner", value: "anxextor Web Security Scanner" },
    { label: "Scan Duration", value: `${safeResult.timing_ms}ms` },
    { label: "Assessment Scope", value: "Web-based automated security assessment" },
  ];
  
  metaItems.forEach(item => {
    const p = doc.createElement("p");
    p.innerHTML = `<strong>${item.label}:</strong> ${item.value}`;
    metadata.appendChild(p);
  });
  
  body.appendChild(metadata);

  // Consultant Contact Box
  const consultant = doc.createElement("div");
  consultant.className = "consultant";
  const consultantLabel = doc.createElement("div");
  consultantLabel.className = "consultant-label";
  consultantLabel.textContent = "Security Consultation & Remediation Support";
  consultant.appendChild(consultantLabel);
  const consultantEmail = doc.createElement("div");
  consultantEmail.className = "consultant-email";
  consultantEmail.textContent = "iam@sebastine.com";
  consultant.appendChild(consultantEmail);
  const disclaimer = doc.createElement("p");
  disclaimer.style.marginTop = "10px";
  disclaimer.style.fontSize = "10pt";
  disclaimer.style.color = "#666";
  disclaimer.textContent = "This report is generated automatically and should be reviewed by security professionals.";
  consultant.appendChild(disclaimer);
  body.appendChild(consultant);

  doc.close();
  printWindow.focus();
  setTimeout(() => printWindow.print(), 250);
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
