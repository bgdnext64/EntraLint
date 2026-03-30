# ruff: noqa: E501
"""Standalone HTML report formatter.

Produces a single self-contained HTML file with:
- Embedded CSS (no external dependencies)
- Embedded scan data as a JSON blob
- Interactive severity/category/status filtering
- Severity distribution donut chart (pure SVG, no Chart.js dependency)
- Expandable finding detail rows with remediation + framework mappings
"""

from __future__ import annotations

import html
import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from entralint.core.check import Finding


def format_html(
    findings: list[Finding],
    *,
    tenant_id: str = "",
    check_metadata: dict[str, Any] | None = None,
) -> str:
    """Serialize findings to a self-contained HTML report."""
    from entralint.core.check import Severity, Status

    now = datetime.now(UTC).isoformat()

    # Summary counts
    total = len(findings)
    passed = sum(1 for f in findings if f.status == Status.PASS)
    failed = sum(1 for f in findings if f.status == Status.FAIL)
    skipped = sum(
        1
        for f in findings
        if f.status
        in (Status.SKIPPED_LICENSE, Status.SKIPPED_PERMISSION, Status.SKIPPED_DEPENDENCY)
    )
    errors = sum(1 for f in findings if f.status == Status.ERROR)

    # Severity breakdown (failures only)
    sev_counts: dict[str, int] = {s.value: 0 for s in Severity}
    for f in findings:
        if f.status == Status.FAIL:
            sev_counts[f.severity.value] += 1

    # Category breakdown (failures only)
    cat_counts: dict[str, int] = {}
    for f in findings:
        if f.status == Status.FAIL:
            cat = f.check_id.split("_")[1] if "_" in f.check_id else "other"
            cat_counts[cat] = cat_counts.get(cat, 0) + 1

    # Build findings JSON for embedded data
    findings_data = []
    for f in findings:
        fd: dict[str, Any] = {
            "check_id": f.check_id,
            "status": f.status.value,
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description,
            "remediation": f.remediation,
            "resource_id": f.resource_id or "",
            "resource_type": f.resource_type or "",
            "frameworks": [
                {"framework": fw.framework, "controls": fw.controls}
                for fw in f.frameworks
            ],
        }
        # Enrich from metadata if available
        meta = (check_metadata or {}).get(f.check_id)
        if meta:
            fd["risk"] = meta.get("risk", "")
            fd["remediation_url"] = meta.get("remediation", {}).get("url", "")
        findings_data.append(fd)

    scan_data = json.dumps(
        {
            "generated_at": now,
            "tenant_id": tenant_id,
            "summary": {
                "total": total,
                "passed": passed,
                "failed": failed,
                "skipped": skipped,
                "errors": errors,
            },
            "severity_counts": sev_counts,
            "category_counts": cat_counts,
            "findings": findings_data,
        },
        indent=None,
    )

    return _TEMPLATE.replace("{{SCAN_DATA}}", scan_data).replace(
        "{{GENERATED_AT}}", html.escape(now)
    ).replace(
        "{{TENANT_ID}}", html.escape(tenant_id or "Unknown")
    ).replace(
        "{{TOTAL}}", str(total)
    ).replace(
        "{{PASSED}}", str(passed)
    ).replace(
        "{{FAILED}}", str(failed)
    ).replace(
        "{{SKIPPED}}", str(skipped)
    ).replace(
        "{{ERRORS}}", str(errors)
    ).replace(
        "{{ERRORS_DISPLAY}}", "block" if errors > 0 else "none"
    )


_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>EntraLint Security Report</title>
<style>
  :root {
    --bg: #0f172a; --surface: #1e293b; --surface2: #334155;
    --text: #e2e8f0; --dim: #94a3b8; --border: #475569;
    --critical: #ef4444; --high: #f97316; --medium: #eab308;
    --low: #3b82f6; --pass: #22c55e; --skip: #6b7280;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.5;
    padding: 2rem; max-width: 1400px; margin: 0 auto;
  }
  header {
    display: flex; justify-content: space-between; align-items: center;
    padding-bottom: 1.5rem; border-bottom: 1px solid var(--border);
    margin-bottom: 2rem;
  }
  header h1 { font-size: 1.5rem; font-weight: 700; }
  header h1 span { color: var(--critical); }
  .meta { font-size: 0.85rem; color: var(--dim); text-align: right; }

  /* Summary cards */
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .card {
    background: var(--surface); border-radius: 8px; padding: 1.25rem;
    text-align: center; border: 1px solid var(--border);
  }
  .card .value { font-size: 2rem; font-weight: 700; }
  .card .label { font-size: 0.8rem; color: var(--dim); text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.25rem; }
  .card.failed .value { color: var(--critical); }
  .card.passed .value { color: var(--pass); }
  .card.skipped .value { color: var(--skip); }

  /* Charts row */
  .charts { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 2rem; }
  .chart-box {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 1.5rem;
  }
  .chart-box h3 { font-size: 0.9rem; color: var(--dim); margin-bottom: 1rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .donut-wrap { display: flex; align-items: center; justify-content: center; gap: 2rem; }
  .legend { display: flex; flex-direction: column; gap: 0.5rem; }
  .legend-item { display: flex; align-items: center; gap: 0.5rem; font-size: 0.85rem; }
  .legend-dot { width: 12px; height: 12px; border-radius: 3px; }

  /* Category bars */
  .bar-list { display: flex; flex-direction: column; gap: 0.6rem; }
  .bar-row { display: flex; align-items: center; gap: 0.75rem; }
  .bar-label { width: 90px; font-size: 0.85rem; text-align: right; color: var(--dim); text-transform: capitalize; }
  .bar-track { flex: 1; height: 24px; background: var(--surface2); border-radius: 4px; overflow: hidden; }
  .bar-fill { height: 100%; background: var(--critical); border-radius: 4px; transition: width 0.3s; display: flex; align-items: center; padding-left: 8px; font-size: 0.75rem; font-weight: 600; min-width: fit-content; }

  /* Filters */
  .filters {
    display: flex; gap: 0.75rem; margin-bottom: 1rem; flex-wrap: wrap; align-items: center;
  }
  .filters label { font-size: 0.8rem; color: var(--dim); }
  .filters select, .filters input {
    background: var(--surface); color: var(--text); border: 1px solid var(--border);
    border-radius: 6px; padding: 0.4rem 0.75rem; font-size: 0.85rem;
  }
  .filters input { width: 220px; }

  /* Findings table */
  .findings-table { width: 100%; border-collapse: collapse; }
  .findings-table th {
    text-align: left; padding: 0.6rem 0.75rem; font-size: 0.75rem;
    color: var(--dim); text-transform: uppercase; letter-spacing: 0.05em;
    border-bottom: 2px solid var(--border); cursor: pointer; user-select: none;
  }
  .findings-table th:hover { color: var(--text); }
  .findings-table td { padding: 0.6rem 0.75rem; border-bottom: 1px solid var(--surface2); font-size: 0.85rem; vertical-align: top; }
  .findings-table tr.finding-row { cursor: pointer; }
  .findings-table tr.finding-row:hover { background: var(--surface); }
  .sev-badge {
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 0.75rem; font-weight: 700; text-transform: uppercase;
  }
  .sev-CRITICAL { background: #7f1d1d; color: #fca5a5; }
  .sev-HIGH { background: #7c2d12; color: #fdba74; }
  .sev-MEDIUM { background: #713f12; color: #fde047; }
  .sev-LOW { background: #1e3a5f; color: #93c5fd; }
  .status-PASS { color: var(--pass); }
  .status-FAIL { color: var(--critical); }
  .status-SKIP { color: var(--skip); }
  .status-ERROR { color: var(--critical); font-weight: 700; }

  /* Detail row */
  .detail-row { display: none; }
  .detail-row.open { display: table-row; }
  .detail-cell { padding: 1rem 0.75rem 1.25rem 2.5rem; background: var(--surface); }
  .detail-cell h4 { font-size: 0.8rem; color: var(--dim); text-transform: uppercase; margin: 0.75rem 0 0.25rem 0; }
  .detail-cell h4:first-child { margin-top: 0; }
  .detail-cell p { font-size: 0.85rem; margin-bottom: 0.25rem; }
  .detail-cell a { color: var(--low); }
  .fw-tag {
    display: inline-block; background: var(--surface2); border-radius: 4px;
    padding: 2px 8px; font-size: 0.75rem; margin: 2px 4px 2px 0;
  }

  /* Footer */
  footer { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border); font-size: 0.8rem; color: var(--dim); text-align: center; }

  @media (max-width: 800px) {
    body { padding: 1rem; }
    .charts { grid-template-columns: 1fr; }
    .cards { grid-template-columns: repeat(2, 1fr); }
    .donut-wrap { flex-direction: column; }
  }
</style>
</head>
<body>
<header>
  <h1>Entra<span>Lint</span> Security Report</h1>
  <div class="meta">
    <div>Tenant: {{TENANT_ID}}</div>
    <div>Generated: {{GENERATED_AT}}</div>
    <div>EntraLint v0.1.0</div>
  </div>
</header>

<!-- Summary cards -->
<div class="cards">
  <div class="card"><div class="value">{{TOTAL}}</div><div class="label">Total Findings</div></div>
  <div class="card failed"><div class="value">{{FAILED}}</div><div class="label">Failed</div></div>
  <div class="card passed"><div class="value">{{PASSED}}</div><div class="label">Passed</div></div>
  <div class="card skipped"><div class="value">{{SKIPPED}}</div><div class="label">Skipped</div></div>
  <div class="card" style="display:{{ERRORS_DISPLAY}}"><div class="value" style="color:var(--critical)">{{ERRORS}}</div><div class="label">Errors</div></div>
</div>

<!-- Charts -->
<div class="charts">
  <div class="chart-box">
    <h3>Severity Distribution</h3>
    <div class="donut-wrap">
      <svg id="donut" width="160" height="160" viewBox="0 0 36 36"></svg>
      <div class="legend" id="sev-legend"></div>
    </div>
  </div>
  <div class="chart-box">
    <h3>Failures by Category</h3>
    <div class="bar-list" id="cat-bars"></div>
  </div>
</div>

<!-- Filters -->
<div class="filters">
  <label>Status:</label>
  <select id="filter-status">
    <option value="all">All</option>
    <option value="FAIL" selected>Failed</option>
    <option value="PASS">Passed</option>
    <option value="SKIP">Skipped</option>
  </select>
  <label>Severity:</label>
  <select id="filter-sev">
    <option value="all">All</option>
    <option value="CRITICAL">Critical</option>
    <option value="HIGH">High</option>
    <option value="MEDIUM">Medium</option>
    <option value="LOW">Low</option>
  </select>
  <label>Search:</label>
  <input type="text" id="filter-search" placeholder="Filter by check ID, title..." />
  <span id="result-count" style="font-size:0.8rem;color:var(--dim)"></span>
</div>

<!-- Findings table -->
<table class="findings-table">
  <thead>
    <tr>
      <th data-sort="severity" style="width:100px">Severity</th>
      <th data-sort="status" style="width:70px">Status</th>
      <th data-sort="check_id" style="width:180px">Check ID</th>
      <th data-sort="title">Title</th>
      <th data-sort="resource_id">Resource</th>
    </tr>
  </thead>
  <tbody id="findings-body"></tbody>
</table>

<footer>
  Generated by <strong>EntraLint v0.1.0</strong> &mdash; Open-source Entra ID security linter
</footer>

<script>
const SCAN_DATA = {{SCAN_DATA}};

// --- Donut chart (SVG) ---
(function() {
  const svg = document.getElementById('donut');
  const legend = document.getElementById('sev-legend');
  const sc = SCAN_DATA.severity_counts;
  const items = [
    { label: 'Critical', count: sc.CRITICAL || 0, color: '#ef4444' },
    { label: 'High', count: sc.HIGH || 0, color: '#f97316' },
    { label: 'Medium', count: sc.MEDIUM || 0, color: '#eab308' },
    { label: 'Low', count: sc.LOW || 0, color: '#3b82f6' },
  ];
  const total = items.reduce((a, b) => a + b.count, 0);
  if (total === 0) {
    svg.innerHTML = '<text x="18" y="20" text-anchor="middle" fill="#94a3b8" font-size="4">No failures</text>';
    return;
  }
  let cum = 0;
  items.forEach(item => {
    if (item.count === 0) return;
    const pct = item.count / total;
    const dash = pct * 100;
    const offset = -cum * 100 + 25; // 25 offset rotates to 12 o'clock
    cum += pct;
    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', '18'); circle.setAttribute('cy', '18');
    circle.setAttribute('r', '15.915');
    circle.setAttribute('fill', 'none');
    circle.setAttribute('stroke', item.color);
    circle.setAttribute('stroke-width', '3.5');
    circle.setAttribute('stroke-dasharray', dash + ' ' + (100 - dash));
    circle.setAttribute('stroke-dashoffset', String(offset));
    svg.appendChild(circle);
    // Legend
    legend.innerHTML += '<div class="legend-item"><div class="legend-dot" style="background:' + item.color + '"></div>' + item.label + ': ' + item.count + '</div>';
  });
  // Center text
  svg.innerHTML += '<text x="18" y="19" text-anchor="middle" fill="#e2e8f0" font-size="6" font-weight="700">' + total + '</text><text x="18" y="22.5" text-anchor="middle" fill="#94a3b8" font-size="2.5">failures</text>';
})();

// --- Category bars ---
(function() {
  const bars = document.getElementById('cat-bars');
  const cc = SCAN_DATA.category_counts;
  const entries = Object.entries(cc).sort((a, b) => b[1] - a[1]);
  const max = entries.length > 0 ? entries[0][1] : 1;
  const catColors = { ca: '#ef4444', app: '#f97316', sp: '#eab308', role: '#a855f7', user: '#3b82f6', org: '#22c55e', auth: '#06b6d4' };
  entries.forEach(([cat, count]) => {
    const pct = Math.max((count / max) * 100, 8);
    const color = catColors[cat] || '#6b7280';
    bars.innerHTML += '<div class="bar-row"><div class="bar-label">' + cat + '</div><div class="bar-track"><div class="bar-fill" style="width:' + pct + '%;background:' + color + '">' + count + '</div></div></div>';
  });
  if (entries.length === 0) bars.innerHTML = '<div style="color:#94a3b8;font-size:0.85rem">No failures detected</div>';
})();

// --- Findings table ---
const tbody = document.getElementById('findings-body');
const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
let sortKey = 'severity', sortAsc = true;

function statusGroup(s) {
  if (s === 'FAIL') return 'FAIL';
  if (s === 'PASS') return 'PASS';
  return 'SKIP';
}

function renderFindings() {
  const statusFilter = document.getElementById('filter-status').value;
  const sevFilter = document.getElementById('filter-sev').value;
  const search = document.getElementById('filter-search').value.toLowerCase();

  let data = SCAN_DATA.findings.filter(f => {
    if (statusFilter !== 'all' && statusGroup(f.status) !== statusFilter) return false;
    if (sevFilter !== 'all' && f.severity !== sevFilter) return false;
    if (search && !(f.check_id + ' ' + f.title + ' ' + f.resource_id).toLowerCase().includes(search)) return false;
    return true;
  });

  // Sort
  data.sort((a, b) => {
    let va, vb;
    if (sortKey === 'severity') { va = sevOrder[a.severity] ?? 9; vb = sevOrder[b.severity] ?? 9; }
    else { va = (a[sortKey] || '').toLowerCase(); vb = (b[sortKey] || '').toLowerCase(); }
    if (va < vb) return sortAsc ? -1 : 1;
    if (va > vb) return sortAsc ? 1 : -1;
    return 0;
  });

  document.getElementById('result-count').textContent = data.length + ' of ' + SCAN_DATA.findings.length + ' findings';

  let html = '';
  data.forEach((f, i) => {
    const sg = statusGroup(f.status);
    const statusText = sg === 'SKIP' ? 'SKIP' : f.status;
    html += '<tr class="finding-row" data-idx="' + i + '" onclick="toggleDetail(' + i + ')">';
    html += '<td><span class="sev-badge sev-' + f.severity + '">' + f.severity + '</span></td>';
    html += '<td class="status-' + sg + '">' + statusText + '</td>';
    html += '<td style="font-family:monospace;font-size:0.8rem">' + esc(f.check_id) + '</td>';
    html += '<td>' + esc(f.title) + '</td>';
    html += '<td style="color:var(--dim);font-size:0.8rem">' + esc(f.resource_id) + '</td>';
    html += '</tr>';
    // Detail row
    html += '<tr class="detail-row" id="detail-' + i + '"><td colspan="5" class="detail-cell">';
    if (f.description) html += '<h4>Description</h4><p>' + esc(f.description) + '</p>';
    if (f.risk) html += '<h4>Risk</h4><p>' + esc(f.risk) + '</p>';
    if (f.remediation) html += '<h4>Remediation</h4><p>' + esc(f.remediation) + '</p>';
    if (f.remediation_url) html += '<p><a href="' + esc(f.remediation_url) + '" target="_blank" rel="noopener">' + esc(f.remediation_url) + '</a></p>';
    if (f.frameworks && f.frameworks.length > 0) {
      html += '<h4>Frameworks</h4>';
      f.frameworks.forEach(fw => {
        fw.controls.forEach(c => { html += '<span class="fw-tag">' + esc(fw.framework) + ' ' + esc(c) + '</span>'; });
      });
    }
    html += '</td></tr>';
  });
  tbody.innerHTML = html;
}

function esc(s) { const d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; }

function toggleDetail(i) {
  const el = document.getElementById('detail-' + i);
  if (el) el.classList.toggle('open');
}

// Sort headers
document.querySelectorAll('.findings-table th[data-sort]').forEach(th => {
  th.addEventListener('click', () => {
    const key = th.dataset.sort;
    if (sortKey === key) sortAsc = !sortAsc;
    else { sortKey = key; sortAsc = true; }
    renderFindings();
  });
});

// Filters
document.getElementById('filter-status').addEventListener('change', renderFindings);
document.getElementById('filter-sev').addEventListener('change', renderFindings);
document.getElementById('filter-search').addEventListener('input', renderFindings);

// Hide errors card if zero
if (SCAN_DATA.summary.errors === 0) {
  document.querySelectorAll('.card').forEach(c => {
    if (c.style.display !== undefined && c.innerHTML.includes('Errors')) c.style.display = 'none';
  });
}

renderFindings();
</script>
</body>
</html>
"""
