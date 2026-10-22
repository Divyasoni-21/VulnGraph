
const form = document.getElementById("repo-form");
const input = document.getElementById("repo-url");
const scanButton = document.getElementById("scan-button");
const statusEl = document.getElementById("status");
const errorEl = document.getElementById("error");

let lastResult = null;

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function showView(viewName) {
  const names = ["overview", "findings", "report"];

  for (const name of names) {
    document.getElementById(`${name}-view`)
      .classList.toggle("hidden", name !== viewName);
  }

  document.querySelectorAll(".nav-item").forEach((button) => {
    button.classList.toggle("active", button.dataset.view === viewName);
  });

  const titles = {
    overview: "Repository overview",
    findings: "Security findings",
    report: "AI security report",
  };

  document.getElementById("page-title").textContent = titles[viewName];
}

document.querySelectorAll("[data-view]").forEach((button) => {
  button.addEventListener("click", () => showView(button.dataset.view));
});

function buildFindingCard(finding, compact = false) {
  const card = el("article", "finding-preview");
  const title = el("strong", "", finding.title);
  const badge = el("span", `severity ${finding.severity}`, finding.severity);
  const location = el(
    "div",
    "file-line",
    `${finding.file} : ${finding.line}`
  );

  card.append(title, badge, location);

  if (!compact) {
    const evidence = el("div", "file-line");
    evidence.style.gridColumn = "1 / -1";
    evidence.textContent = finding.evidence || "";
    card.append(evidence);

    const recommendation = el("div", "file-line");
    recommendation.style.gridColumn = "1 / -1";
    recommendation.textContent = `Suggested fix: ${finding.recommendation}`;
    card.append(recommendation);

    const confidence = el(
      "div",
      "confidence",
      `Confidence: ${finding.confidence || "Unrated"}`
    );
    confidence.style.gridColumn = "1 / -1";
    card.append(confidence);
  }

  return card;
}

function renderResults(data) {
  lastResult = data;

  document.getElementById("repo-label").textContent = data.repository;
  document.getElementById("files-count").textContent = data.files_scanned;
  document.getElementById("findings-count").textContent = data.findings_count;
  document.getElementById("high-count").textContent = data.high_count;
  document.getElementById("sidebar-count").textContent = data.findings_count;
  document.getElementById("finding-total").textContent =
    `${data.findings_count} RESULTS`;
  document.getElementById("notice").textContent = data.notice;
  document.getElementById("ai-report").textContent = data.ai_report;

  const preview = document.getElementById("preview-list");
  preview.replaceChildren();

  if (!data.findings.length) {
    const empty = el("div", "empty-state");
    empty.append(
      el("div", "empty-icon", "✓"),
      el("strong", "", "No configured patterns detected"),
      el("p", "", "This is not proof that the repository is secure.")
    );
    preview.append(empty);
  } else {
    data.findings.slice(0, 5).forEach((finding) => {
      preview.append(buildFindingCard(finding, true));
    });
  }

  const table = document.getElementById("findings-table");
  table.replaceChildren();

  if (!data.findings.length) {
    const row = el("tr");
    const cell = el(
      "td",
      "table-empty",
      "No configured patterns matched. Manual review is still recommended."
    );
    cell.colSpan = 4;
    row.append(cell);
    table.append(row);
  } else {
    data.findings.forEach((finding, index) => {
      const row = el("tr");
      const severityCell = el("td");
      severityCell.append(el(
        "span",
        `severity ${finding.severity}`,
        finding.severity
      ));

      const findingCell = el("td");
      findingCell.append(el("div", "finding-name", finding.title));
      findingCell.append(el("span", "evidence", finding.evidence));

      const fileCell = el(
        "td",
        "file-cell",
        `${finding.file}\nLine ${finding.line}`
      );
      fileCell.style.whiteSpace = "pre-line";

      const confidenceCell = el(
        "td",
        "confidence",
        finding.confidence || "Unrated"
      );

      row.append(severityCell, findingCell, fileCell, confidenceCell);
      row.tabIndex = 0;
      row.setAttribute("role", "button");
      row.setAttribute("aria-label", `Show details for ${finding.title}`);

      const openDetails = () => {
        const detail = document.getElementById("finding-detail");
        detail.replaceChildren(
          el("h4", "", `${finding.title} — ${finding.file}:${finding.line}`),
          el("p", "", `Evidence: ${finding.evidence}`),
          el("p", "", `Suggested fix: ${finding.recommendation}`),
          el(
            "p",
            "",
            "This is a static pattern match. Verify the surrounding code before treating it as an exploitable vulnerability."
          )
        );
        detail.classList.remove("hidden");
      };

      row.addEventListener("click", openDetails);
      row.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          openDetails();
        }
      });

      table.append(row);
    });
  }

  document.getElementById("finding-detail").classList.add("hidden");
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  errorEl.textContent = "";
  statusEl.textContent = "Fetching repository and scanning Python files…";
  scanButton.disabled = true;
  scanButton.textContent = "Scanning…";

  try {
    const response = await fetch("/api/repo-scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: input.value.trim() }),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Repository scan failed.");
    }

    renderResults(data);
    statusEl.textContent = "Scan completed successfully.";
    showView("overview");
  } catch (error) {
    errorEl.textContent = error.message || "Unable to scan repository.";
    statusEl.textContent = "";
  } finally {
    scanButton.disabled = false;
    scanButton.innerHTML = 'Analyze repository <span>↗</span>';
  }
});
