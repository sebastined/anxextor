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

const HISTORY_KEY = "anxextor.history";
const THEME_KEY = "anxextor.theme";
let lastResult = null;

const sanitizeText = (value) =>
  String(value ?? "").replace(/[<>]/g, "").trim();

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

const renderKeyValue = (target, data) => {
  target.innerHTML = "";
  Object.entries(data || {}).forEach(([key, value]) => {
    const row = document.createElement("div");
    const label = document.createElement("span");
    const val = document.createElement("span");

    label.textContent = `${key}: `;
    val.textContent = value ?? "n/a";

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

    li.classList.add(finding.severity);
    title.textContent = finding.title;
    description.textContent = finding.description;
    recommendation.textContent = finding.recommendation;

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
    if (counts[finding.severity] !== undefined) {
      counts[finding.severity] += 1;
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
    if (!finding.recommendation || seen.has(finding.recommendation)) {
      return;
    }
    seen.add(finding.recommendation);
    const li = document.createElement("li");
    li.textContent = finding.recommendation;
    remediationEl.appendChild(li);
  });
  if (!remediationEl.children.length) {
    const li = document.createElement("li");
    li.textContent = "No remediation steps needed.";
    remediationEl.appendChild(li);
  }
};

const renderHistory = () => {
  const history = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
  historyEl.innerHTML = "";
  history.forEach((entry) => {
    const li = document.createElement("li");
    const title = document.createElement("strong");
    const meta = document.createElement("span");

    const host = sanitizeText(entry.host);
    const timestamp = sanitizeText(entry.timestamp);

    title.textContent = host;
    meta.textContent = timestamp;

    li.appendChild(title);
    li.appendChild(meta);
    li.addEventListener("click", () => {
      const targetInput = document.getElementById("target-input");
      targetInput.value = host;
      form.requestSubmit();
    });
    historyEl.appendChild(li);
  });
};

const saveHistory = (data) => {
  const history = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
  const safeData = sanitizeResult(data);
  const host = new URL(safeData.final_url).host;
  history.unshift({
    host,
    timestamp: new Date().toLocaleString(),
  });
  localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, 6)));
  renderHistory();
};

const renderResult = (data, save = true) => {
  const safeData = sanitizeResult(data);
  lastResult = safeData;
  scoreEl.textContent = safeData.score;
  gradeEl.textContent = safeData.grade;
  timingEl.textContent = `Completed in ${safeData.timing_ms} ms`;
  scoreFillEl.style.width = `${safeData.score}%`;

  renderFindings(safeData.findings);
  renderSummary(safeData.findings);
  renderRemediation(safeData.findings);
  renderKeyValue(tlsEl, safeData.tls || { status: "Not available" });
  renderKeyValue(dnsEl, safeData.dns || {});

  resultsSection.hidden = false;
  statusEl.textContent = `Scan complete for ${safeData.final_url}`;

  if (save) {
    saveHistory(safeData);
  }
};

copyBtn.addEventListener("click", async () => {
  if (!lastResult) {
    return;
  }
  try {
    await navigator.clipboard.writeText(JSON.stringify(lastResult, null, 2));
    statusEl.textContent = "JSON copied to clipboard.";
  } catch (error) {
    statusEl.textContent = "Copy failed."
  }
});

downloadBtn.addEventListener("click", () => {
  if (!lastResult) {
    return;
  }
  const blob = new Blob([JSON.stringify(lastResult, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "scan-result.json";
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
});

csvBtn.addEventListener("click", () => {
  if (!lastResult) {
    return;
  }
  const rows = [
    ["id", "title", "severity", "description", "recommendation"],
    ...lastResult.findings.map((finding) => [
      finding.id,
      finding.title,
      finding.severity,
      finding.description,
      finding.recommendation,
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
  const link = document.createElement("a");
  link.href = url;
  link.download = "scan-findings.csv";
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
});

pdfBtn.addEventListener("click", () => {
  if (!lastResult) {
    return;
  }
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
  meta.textContent = `Target: ${lastResult.final_url} | Score: ${lastResult.score} | Grade: ${lastResult.grade}`;
  body.appendChild(meta);

  const listTitle = doc.createElement("h2");
  listTitle.textContent = "Findings";
  body.appendChild(listTitle);

  const list = doc.createElement("ol");
  lastResult.findings.forEach((finding) => {
    const li = doc.createElement("li");
    li.textContent = `${finding.severity.toUpperCase()}: ${finding.title} - ${finding.recommendation}`;
    list.appendChild(li);
  });
  body.appendChild(list);

  const remediationTitle = doc.createElement("h2");
  remediationTitle.textContent = "Remediation";
  body.appendChild(remediationTitle);

  const remList = doc.createElement("ol");
  remediationEl.childNodes.forEach((node) => {
    const li = doc.createElement("li");
    li.textContent = node.textContent || "";
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

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  statusEl.textContent = "Scanning...";
  resultsSection.hidden = true;

  const url = document.getElementById("target-input").value;
  const apiKey = document.getElementById("api-key-input").value;
  try {
    const headers = { "Content-Type": "application/json" };
    if (apiKey) {
      headers["X-API-Key"] = apiKey;
    }

    const response = await fetch("/api/scan", {
      method: "POST",
      headers,
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || "Scan failed");
    }

    const data = await response.json();
    renderResult(data, true);
  } catch (error) {
    statusEl.textContent = error.message;
  }
});

renderHistory();
setTheme(localStorage.getItem(THEME_KEY) || "dark");
