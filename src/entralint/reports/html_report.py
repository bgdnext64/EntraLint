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

    # Safely embed the JSON inside an inline <script> block. Without this,
    # a finding containing "</script>" (or similar) could break out of the
    # script tag and inject arbitrary HTML/JS into the report (XSS).
    # The replacements below keep the string valid JSON *and* valid inside a
    # <script> context. U+2028 / U+2029 are also escaped because they
    # terminate JS string literals even though JSON permits them raw.
    scan_data = (
        scan_data.replace("<!--", "\\u003C!--")
        .replace("<script", "\\u003Cscript")
        .replace("</script", "\\u003C/script")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
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
    --azure: #0078d4; --azure-dark: #005a9e; --azure-light: #deecf9;
    --bg: #f3f2f1; --surface: #ffffff; --surface-hover: #faf9f8;
    --text: #323130; --text-secondary: #605e5c; --text-light: #a19f9d;
    --border: #edebe9; --border-strong: #d2d0ce;
    --critical: #d13438; --critical-bg: #fde7e9;
    --high: #ca5010; --high-bg: #fff4ce;
    --medium: #8a8886; --medium-bg: #f3f2f1;
    --low: #0078d4; --low-bg: #deecf9;
    --pass: #107c10; --pass-bg: #dff6dd;
    --skip: #8a8886;
    --radius: 4px; --shadow: 0 1.6px 3.6px 0 rgba(0,0,0,.132), 0 0.3px 0.9px 0 rgba(0,0,0,.108);
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, 'Helvetica Neue', sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.5;
    -webkit-font-smoothing: antialiased;
  }

  /* Top bar */
  .topbar {
    background: var(--azure); color: #fff; padding: 0 2rem;
    height: 48px; display: flex; align-items: center; gap: 1.5rem;
  }
  .topbar h1 {
    font-size: 1rem; font-weight: 600; letter-spacing: -0.01em; margin-right: 1rem;
  }
  .topbar h1 span { font-weight: 400; opacity: 0.85; }

  /* Tab navigation */
  .tab-nav { display: flex; gap: 0; height: 100%; }
  .tab-btn {
    background: none; border: none; color: rgba(255,255,255,0.75); font-family: inherit;
    font-size: 0.8125rem; font-weight: 600; padding: 0 1rem; cursor: pointer;
    height: 48px; display: flex; align-items: center; position: relative;
    transition: color 0.15s;
  }
  .tab-btn:hover { color: #fff; }
  .tab-btn.active { color: #fff; }
  .tab-btn.active::after {
    content: ''; position: absolute; bottom: 0; left: 0; right: 0;
    height: 3px; background: #fff; border-radius: 2px 2px 0 0;
  }

  /* Tab panels */
  .tab-panel { display: none; }
  .tab-panel.active { display: block; }

  /* Page layout */
  .page { max-width: 1360px; margin: 0 auto; padding: 1.5rem 2rem 3rem 2rem; }

  /* Breadcrumb-style subtitle */
  .subtitle {
    font-size: 0.8125rem; color: var(--text-secondary); margin-bottom: 1.25rem;
    display: flex; align-items: center; gap: 0.5rem;
  }
  .subtitle .sep { color: var(--text-light); }

  /* Summary cards */
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
  .card {
    background: var(--surface); border-radius: var(--radius); padding: 1.25rem 1.5rem;
    box-shadow: var(--shadow); border-top: 3px solid var(--border);
  }
  .card .value { font-size: 2.25rem; font-weight: 600; color: var(--text); line-height: 1.1; }
  .card .label { font-size: 0.75rem; color: var(--text-secondary); margin-top: 0.375rem; text-transform: uppercase; letter-spacing: 0.04em; font-weight: 600; }
  .card.failed { border-top-color: var(--critical); }
  .card.failed .value { color: var(--critical); }
  .card.passed { border-top-color: var(--pass); }
  .card.passed .value { color: var(--pass); }
  .card.skipped { border-top-color: var(--skip); }
  .card.skipped .value { color: var(--skip); }
  .card.total { border-top-color: var(--azure); }
  .card.total .value { color: var(--azure); }

  /* Charts row */
  .charts { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem; }
  .chart-box {
    background: var(--surface); border-radius: var(--radius);
    box-shadow: var(--shadow); padding: 1.5rem;
  }
  .chart-box h3 {
    font-size: 0.875rem; font-weight: 600; color: var(--text);
    margin-bottom: 1.25rem; padding-bottom: 0.75rem; border-bottom: 1px solid var(--border);
  }
  .donut-wrap { display: flex; align-items: center; justify-content: center; gap: 2.5rem; }
  .legend { display: flex; flex-direction: column; gap: 0.625rem; }
  .legend-item { display: flex; align-items: center; gap: 0.625rem; font-size: 0.8125rem; color: var(--text); }
  .legend-dot { width: 10px; height: 10px; border-radius: 2px; flex-shrink: 0; }
  .legend-count { font-weight: 600; min-width: 1.5rem; }

  /* Category bars */
  .bar-list { display: flex; flex-direction: column; gap: 0.75rem; }
  .bar-row { display: flex; align-items: center; gap: 0.75rem; }
  .bar-label { width: 100px; font-size: 0.8125rem; text-align: right; color: var(--text-secondary); text-transform: capitalize; font-weight: 600; }
  .bar-track { flex: 1; height: 28px; background: var(--bg); border-radius: var(--radius); overflow: hidden; }
  .bar-fill {
    height: 100%; border-radius: var(--radius); transition: width 0.4s ease;
    display: flex; align-items: center; padding-left: 10px;
    font-size: 0.75rem; font-weight: 600; color: #fff; min-width: fit-content;
  }

  /* Toolbar / Filters */
  .toolbar {
    background: var(--surface); border-radius: var(--radius); box-shadow: var(--shadow);
    padding: 0.875rem 1.25rem; margin-bottom: 1rem;
    display: flex; gap: 1rem; flex-wrap: wrap; align-items: center;
  }
  .toolbar label { font-size: 0.75rem; font-weight: 600; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.03em; }
  .toolbar select, .toolbar input[type="text"] {
    background: var(--surface); color: var(--text); border: 1px solid var(--border-strong);
    border-radius: var(--radius); padding: 6px 10px; font-size: 0.8125rem;
    font-family: inherit; outline: none; transition: border-color 0.15s;
  }
  .toolbar select:focus, .toolbar input:focus { border-color: var(--azure); box-shadow: 0 0 0 1px var(--azure); }
  .toolbar input[type="text"] { width: 240px; }
  .toolbar .filter-group { display: flex; align-items: center; gap: 0.375rem; }
  .result-count { font-size: 0.8125rem; color: var(--text-secondary); margin-left: auto; }

  /* Findings table */
  .table-wrap {
    background: var(--surface); border-radius: var(--radius); box-shadow: var(--shadow);
    overflow: hidden;
  }
  .findings-table { width: 100%; border-collapse: collapse; }
  .findings-table th {
    text-align: left; padding: 0.75rem 1rem; font-size: 0.75rem; font-weight: 600;
    color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.03em;
    background: var(--surface-hover); border-bottom: 1px solid var(--border-strong);
    cursor: pointer; user-select: none; transition: color 0.15s;
  }
  .findings-table th:hover { color: var(--azure); }
  .findings-table th .sort-icon { font-size: 0.625rem; margin-left: 0.25rem; opacity: 0.4; }
  .findings-table td {
    padding: 0.625rem 1rem; border-bottom: 1px solid var(--border);
    font-size: 0.8125rem; vertical-align: middle;
  }
  .findings-table tr.finding-row { cursor: pointer; transition: background 0.1s; }
  .findings-table tr.finding-row:hover { background: var(--surface-hover); }

  /* Severity badges */
  .sev-badge {
    display: inline-block; padding: 3px 10px; border-radius: 2px;
    font-size: 0.6875rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.02em;
  }
  .sev-CRITICAL { background: var(--critical-bg); color: var(--critical); }
  .sev-HIGH { background: var(--high-bg); color: var(--high); }
  .sev-MEDIUM { background: var(--medium-bg); color: var(--text-secondary); }
  .sev-LOW { background: var(--low-bg); color: var(--low); }

  /* Status colors */
  .status-PASS { color: var(--pass); font-weight: 600; }
  .status-FAIL { color: var(--critical); font-weight: 600; }
  .status-SKIP { color: var(--skip); }
  .status-ERROR { color: var(--critical); font-weight: 700; }

  /* Detail row */
  .detail-row { display: none; }
  .detail-row.open { display: table-row; }
  .detail-cell {
    padding: 1.25rem 1rem 1.5rem 3rem; background: var(--surface-hover);
    border-bottom: 1px solid var(--border-strong);
  }
  .detail-cell h4 {
    font-size: 0.6875rem; font-weight: 600; color: var(--text-secondary);
    text-transform: uppercase; letter-spacing: 0.05em;
    margin: 1rem 0 0.375rem 0;
  }
  .detail-cell h4:first-child { margin-top: 0; }
  .detail-cell p { font-size: 0.8125rem; color: var(--text); margin-bottom: 0.25rem; line-height: 1.6; }
  .detail-cell a { color: var(--azure); text-decoration: none; }
  .detail-cell a:hover { text-decoration: underline; }
  .fw-tag {
    display: inline-block; background: var(--azure-light); color: var(--azure-dark);
    border-radius: 2px; padding: 2px 8px; font-size: 0.6875rem; font-weight: 600;
    margin: 3px 4px 3px 0;
  }

  /* Footer */
  footer {
    margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border-strong);
    font-size: 0.75rem; color: var(--text-light); text-align: center;
  }
  footer strong { color: var(--text-secondary); font-weight: 600; }

  /* Guide page */
  .guide { max-width: 820px; }
  .guide h2 {
    font-size: 1.375rem; font-weight: 600; color: var(--text); margin: 2rem 0 0.75rem 0;
    padding-bottom: 0.5rem; border-bottom: 1px solid var(--border);
  }
  .guide h2:first-child { margin-top: 0; }
  .guide h3 { font-size: 1rem; font-weight: 600; color: var(--text); margin: 1.5rem 0 0.5rem 0; }
  .guide p { font-size: 0.875rem; color: var(--text); line-height: 1.7; margin-bottom: 0.75rem; }
  .guide ul, .guide ol { font-size: 0.875rem; color: var(--text); line-height: 1.7; margin: 0 0 0.75rem 1.5rem; }
  .guide li { margin-bottom: 0.375rem; }
  .guide code {
    font-family: Consolas, 'Courier New', monospace; font-size: 0.8125rem;
    background: var(--bg); padding: 2px 6px; border-radius: 3px; color: var(--azure-dark);
  }
  .guide pre {
    background: #1e1e1e; color: #d4d4d4; border-radius: var(--radius);
    padding: 1rem 1.25rem; overflow-x: auto; margin: 0.5rem 0 1rem 0;
    font-family: Consolas, 'Courier New', monospace; font-size: 0.8125rem; line-height: 1.6;
  }
  .guide .card-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 0.75rem; margin: 0.75rem 0 1.25rem 0; }
  .guide .info-card {
    background: var(--surface); border-radius: var(--radius); box-shadow: var(--shadow);
    padding: 1rem 1.25rem; border-left: 3px solid var(--azure);
  }
  .guide .info-card.warn { border-left-color: var(--high); }
  .guide .info-card.ok { border-left-color: var(--pass); }
  .guide .info-card h4 { font-size: 0.8125rem; font-weight: 600; margin-bottom: 0.25rem; }
  .guide .info-card p { font-size: 0.8125rem; margin: 0; color: var(--text-secondary); }
  .guide .check-table { width: 100%; border-collapse: collapse; margin: 0.5rem 0 1.25rem 0; }
  .guide .check-table th {
    text-align: left; padding: 0.5rem 0.75rem; font-size: 0.75rem; font-weight: 600;
    color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.03em;
    background: var(--surface-hover); border-bottom: 1px solid var(--border-strong);
  }
  .guide .check-table td {
    padding: 0.5rem 0.75rem; font-size: 0.8125rem; border-bottom: 1px solid var(--border);
  }

  /* Responsive */
  @media (max-width: 900px) {
    .page { padding: 1rem; }
    .charts { grid-template-columns: 1fr; }
    .cards { grid-template-columns: repeat(2, 1fr); }
    .donut-wrap { flex-direction: column; gap: 1.25rem; }
    .toolbar input[type="text"] { width: 100%; }
  }
  @media (max-width: 600px) {
    .topbar { padding: 0 1rem; }
    .cards { grid-template-columns: 1fr 1fr; }
    .findings-table td, .findings-table th { padding: 0.5rem 0.625rem; font-size: 0.75rem; }
  }

  /* Print */
  @media print {
    body { background: #fff; }
    .topbar { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
    .tab-nav { display: none; }
    .toolbar { display: none; }
    .card, .chart-box, .table-wrap { box-shadow: none; border: 1px solid #d2d0ce; }
    .detail-row.open { display: table-row; }
    .tab-panel { display: block !important; }
    #tab-guide { page-break-before: always; }
  }
</style>
</head>
<body>

<!-- Azure-style top bar with tabs -->
<div class="topbar">
  <h1>EntraLint</h1>
  <nav class="tab-nav">
    <button class="tab-btn active" data-tab="results">Results</button>
    <button class="tab-btn" data-tab="guide">Guide</button>
  </nav>
</div>

<!-- === RESULTS TAB === -->
<div class="tab-panel active" id="tab-results">
<div class="page">

<!-- Subtitle / metadata -->
<div class="subtitle">
  <span>Tenant: <strong>{{TENANT_ID}}</strong></span>
  <span class="sep">&middot;</span>
  <span>{{GENERATED_AT}}</span>
  <span class="sep">&middot;</span>
  <span>EntraLint v0.1.0</span>
</div>

<!-- Summary cards -->
<div class="cards">
  <div class="card total"><div class="value">{{TOTAL}}</div><div class="label">Total Checks</div></div>
  <div class="card failed"><div class="value">{{FAILED}}</div><div class="label">Failed</div></div>
  <div class="card passed"><div class="value">{{PASSED}}</div><div class="label">Passed</div></div>
  <div class="card skipped"><div class="value">{{SKIPPED}}</div><div class="label">Skipped</div></div>
  <div class="card" style="display:{{ERRORS_DISPLAY}};border-top-color:var(--critical)"><div class="value" style="color:var(--critical)">{{ERRORS}}</div><div class="label">Errors</div></div>
</div>

<!-- Charts -->
<div class="charts">
  <div class="chart-box">
    <h3>Severity Distribution</h3>
    <div class="donut-wrap">
      <svg id="donut" width="150" height="150" viewBox="0 0 36 36"></svg>
      <div class="legend" id="sev-legend"></div>
    </div>
  </div>
  <div class="chart-box">
    <h3>Failures by Category</h3>
    <div class="bar-list" id="cat-bars"></div>
  </div>
</div>

<!-- Filters toolbar -->
<div class="toolbar">
  <div class="filter-group">
    <label>Status</label>
    <select id="filter-status">
      <option value="all">All</option>
      <option value="FAIL" selected>Failed</option>
      <option value="PASS">Passed</option>
      <option value="SKIP">Skipped</option>
    </select>
  </div>
  <div class="filter-group">
    <label>Severity</label>
    <select id="filter-sev">
      <option value="all">All</option>
      <option value="CRITICAL">Critical</option>
      <option value="HIGH">High</option>
      <option value="MEDIUM">Medium</option>
      <option value="LOW">Low</option>
    </select>
  </div>
  <div class="filter-group">
    <label>Search</label>
    <input type="text" id="filter-search" placeholder="Filter by check ID, title..." />
  </div>
  <span class="result-count" id="result-count"></span>
</div>

<!-- Findings table -->
<div class="table-wrap">
<table class="findings-table">
  <thead>
    <tr>
      <th data-sort="severity" style="width:105px">Severity <span class="sort-icon">&#9650;&#9660;</span></th>
      <th data-sort="status" style="width:75px">Status</th>
      <th data-sort="check_id" style="width:185px">Check ID</th>
      <th data-sort="title">Title</th>
      <th data-sort="resource_id">Resource</th>
    </tr>
  </thead>
  <tbody id="findings-body"></tbody>
</table>
</div>

<footer>
  Generated by <strong>EntraLint v0.1.0</strong> &mdash; Open-source Entra ID security linter
</footer>

</div><!-- .page -->
</div><!-- #tab-results -->

<!-- === GUIDE TAB === -->
<div class="tab-panel" id="tab-guide">
<div class="page guide">

<h2>What is EntraLint?</h2>
<p>EntraLint is an open-source security linter for <strong>Microsoft Entra ID</strong> (formerly Azure Active Directory). It reads your tenant configuration through the Microsoft Graph API, checks it against security best practices and compliance benchmarks, and reports exactly what needs to be fixed.</p>
<p>Think of it as ESLint or Ruff, but for your identity configuration instead of your code.</p>

<div class="card-grid">
  <div class="info-card"><h4>82 Security Checks</h4><p>Covering 9 categories from Conditional Access to AI Agent Identities</p></div>
  <div class="info-card"><h4>Compliance Mapping</h4><p>CIS Microsoft 365 v5, CISA SCuBA (BOD 25-01), NIST 800-53</p></div>
  <div class="info-card ok"><h4>Read-Only Access</h4><p>EntraLint never modifies your tenant &mdash; it only reads configuration data</p></div>
  <div class="info-card warn"><h4>CI/CD Ready</h4><p>SARIF output for GitHub Code Scanning, exit codes for pipeline gates</p></div>
</div>

<h2>Reading This Report</h2>

<h3>Summary Cards</h3>
<p>The cards at the top show an overview of your scan. <strong>Failed</strong> means a misconfiguration was detected. <strong>Passed</strong> means the check found no issues. <strong>Skipped</strong> means EntraLint could not run the check &mdash; usually because of missing API permissions or a license requirement (e.g., Entra ID P1 or P2).</p>

<h3>Severity Levels</h3>
<div class="card-grid">
  <div class="info-card" style="border-left-color:#d13438"><h4>Critical</h4><p>Immediate risk. Direct path to account takeover or tenant compromise. Fix first.</p></div>
  <div class="info-card" style="border-left-color:#ca5010"><h4>High</h4><p>Significant risk that could be exploited with moderate effort. Fix soon.</p></div>
  <div class="info-card" style="border-left-color:#8a8886"><h4>Medium</h4><p>Defense-in-depth gap or hygiene issue. Plan remediation.</p></div>
  <div class="info-card" style="border-left-color:#0078d4"><h4>Low</h4><p>Governance or documentation gap. Address during regular reviews.</p></div>
</div>

<h3>Findings Table</h3>
<p>Click any row to expand it and see the full description, risk explanation, remediation steps, and compliance framework mappings. Use the filters above the table to narrow results by status, severity, or keyword.</p>

<h2>Security Check Categories</h2>
<table class="check-table">
  <thead><tr><th>Category</th><th>Checks</th><th>What It Covers</th></tr></thead>
  <tbody>
    <tr><td>Conditional Access</td><td>14</td><td>MFA enforcement, legacy auth blocking, device compliance, sign-in/user risk policies, device code flow</td></tr>
    <tr><td>Authentication</td><td>10</td><td>Password protection, banned passwords, SSPR, FIDO2, Authenticator settings, TAP lifetime</td></tr>
    <tr><td>Privileged Roles</td><td>10</td><td>PIM usage, Global Admin count, standing assignments, activation approval, emergency access</td></tr>
    <tr><td>Applications</td><td>9</td><td>Expired/long-lived secrets, excessive Graph permissions, missing owners, unrestricted consent</td></tr>
    <tr><td>Service Principals</td><td>9</td><td>Expired credentials, high-privilege grants, dual credential types, stale service principals</td></tr>
    <tr><td>Users &amp; Guests</td><td>9</td><td>Stale accounts, guest access level, MFA registration, disabled users with active roles</td></tr>
    <tr><td>Organization</td><td>9</td><td>Security defaults, verified domains, cross-tenant trust settings</td></tr>
    <tr><td>Agentic Identity</td><td>12</td><td>AI agent permissions, blueprint scope inheritance, blocked permission enforcement, orphaned/stale agents</td></tr>
  </tbody>
</table>

<h2>Agentic Identity Checks</h2>
<p>EntraLint is the first security scanner to provide dedicated checks for <strong>Microsoft Entra Agent ID</strong> &mdash; the GA platform (March 2026) that gives AI agents their own first-class identity type. These 12 checks cover:</p>
<ul>
  <li>Agents holding dangerous or blocked permissions (e.g., <code>Files.ReadWrite.All</code>, <code>RoleManagement.ReadWrite.Directory</code>)</li>
  <li>Blueprints using <code>allAllowedScopes</code> inheritance (agents inherit any permission)</li>
  <li>Orphaned agents with no owner or sponsor</li>
  <li>Stale agent identities with valid credentials</li>
  <li>External (third-party) agent blueprints operating in your tenant</li>
  <li>Agents using client secrets instead of federated credentials</li>
</ul>

<h2>Understanding Skipped Checks</h2>
<p>A <strong>skipped</strong> check is not a failure &mdash; it means EntraLint could not evaluate the check due to an external constraint:</p>
<ul>
  <li><strong>Missing permission</strong> &mdash; The service principal or user account used for the scan does not have the required Graph API permission. Grant the permission and re-scan.</li>
  <li><strong>Missing license</strong> &mdash; The check requires an Entra ID P1 or P2 feature (e.g., sign-in logs, Identity Protection). Upgrade or suppress the check.</li>
  <li><strong>Dependency</strong> &mdash; A prerequisite check failed, making this check irrelevant until the prerequisite is fixed.</li>
</ul>

<h2>Required Permissions</h2>
<p>EntraLint needs <strong>read-only</strong> access to your tenant. It requires these Microsoft Graph API permissions:</p>
<table class="check-table">
  <thead><tr><th>Permission</th><th>What It Reads</th></tr></thead>
  <tbody>
    <tr><td><code>Directory.Read.All</code></td><td>Users, groups, service principals, organization config</td></tr>
    <tr><td><code>Policy.Read.All</code></td><td>Conditional Access policies, auth methods, authorization policy</td></tr>
    <tr><td><code>Application.Read.All</code></td><td>App registrations, credentials</td></tr>
    <tr><td><code>RoleManagement.Read.Directory</code></td><td>Directory role assignments</td></tr>
    <tr><td><code>AuditLog.Read.All</code></td><td>Sign-in logs (requires Entra ID P1+)</td></tr>
    <tr><td><code>AgentIdentity.Read.All</code></td><td>Agent identities, blueprints, blueprint principals</td></tr>
  </tbody>
</table>
<p style="margin-top:1rem;">Run <code>entralint permissions</code> to see the full list, or generate a ready-to-run grant script:</p>
<pre>
# Show required permissions
entralint permissions

# Generate a PowerShell grant script
entralint permissions -f powershell --client-id YOUR_APP_ID

# Generate an Azure CLI grant script
entralint permissions -f azcli --client-id YOUR_APP_ID
</pre>

<h2>CLI Quick Reference</h2>
<pre>
# Install and run
git clone https://github.com/bgdnext64/EntraLint.git
cd EntraLint &amp;&amp; uv sync
uv run entralint login
uv run entralint scan

# Output formats
uv run entralint scan -f html --output-file report.html
uv run entralint scan -f json --output-file results.json
uv run entralint scan -f sarif --output-file results.sarif

# Filter by severity
uv run entralint scan --severity critical,high

# CI/CD gate (exit non-zero on critical findings)
uv run entralint scan --fail-on critical --quiet -f sarif --output-file results.sarif

# Offline mode (scan cached data, no API calls)
uv run entralint scan --offline

# Inspect a specific check
uv run entralint explain entraid_ca_001

# Show required permissions / generate grant scripts
uv run entralint permissions
uv run entralint permissions -f powershell --client-id YOUR_APP_ID
</pre>

<h2>GitHub Action</h2>
<p>EntraLint ships as a reusable GitHub Action. Add it to any workflow to scan your tenant on a schedule and see results in GitHub Code Scanning:</p>
<pre>
# .github/workflows/entralint.yml
- uses: bgdnext64/EntraLint@main
  with:
    tenant-id: ${{ secrets.ENTRALINT_TENANT_ID }}
    client-id: ${{ secrets.ENTRALINT_CLIENT_ID }}
    client-secret: ${{ secrets.ENTRALINT_CLIENT_SECRET }}
    fail-on: high
</pre>
<p>For non-GitHub CI, set <code>ENTRALINT_TENANT_ID</code>, <code>ENTRALINT_CLIENT_ID</code>, and <code>ENTRALINT_CLIENT_SECRET</code> as environment variables. The scan command auto-detects them.</p>

<h2>Configuration</h2>
<p>Create a <code>.entralint.yaml</code> file to customize behavior &mdash; suppress checks, override severities, set CI thresholds, or add custom check directories:</p>
<pre>
suppress:
  - check_id: ca_003
    reason: "Legacy VPN exception approved by CISO"

overrides:
  ca_001:
    severity: critical

exclude_checks:
  - org_001

fail_on: high
baseline: .entralint-baseline.json
</pre>

<h2>Getting Help</h2>
<p>EntraLint is open source and available at <a href="https://github.com/bgdnext64/EntraLint" style="color:var(--azure)">github.com/bgdnext64/EntraLint</a>. File issues, contribute checks, or read the full documentation there.</p>

<footer>
  Generated by <strong>EntraLint v0.1.0</strong> &mdash; Open-source Entra ID security linter
</footer>

</div><!-- .page .guide -->
</div><!-- #tab-guide -->

<script>
const SCAN_DATA = {{SCAN_DATA}};

// --- Donut chart (SVG) ---
(function() {
  const svg = document.getElementById('donut');
  const legend = document.getElementById('sev-legend');
  const sc = SCAN_DATA.severity_counts;
  const items = [
    { label: 'Critical', count: sc.CRITICAL || 0, color: '#d13438' },
    { label: 'High', count: sc.HIGH || 0, color: '#ca5010' },
    { label: 'Medium', count: sc.MEDIUM || 0, color: '#8a8886' },
    { label: 'Low', count: sc.LOW || 0, color: '#0078d4' },
  ];
  const total = items.reduce((a, b) => a + b.count, 0);
  if (total === 0) {
    svg.innerHTML = '<text x="18" y="20" text-anchor="middle" fill="#a19f9d" font-size="3.5" font-family="Segoe UI,sans-serif">No failures</text>';
    return;
  }
  let cum = 0;
  items.forEach(item => {
    if (item.count === 0) return;
    const pct = item.count / total;
    const dash = pct * 100;
    const offset = -cum * 100 + 25;
    cum += pct;
    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', '18'); circle.setAttribute('cy', '18');
    circle.setAttribute('r', '15.915');
    circle.setAttribute('fill', 'none');
    circle.setAttribute('stroke', item.color);
    circle.setAttribute('stroke-width', '3');
    circle.setAttribute('stroke-dasharray', dash + ' ' + (100 - dash));
    circle.setAttribute('stroke-dashoffset', String(offset));
    svg.appendChild(circle);
    legend.innerHTML += '<div class="legend-item"><div class="legend-dot" style="background:' + item.color + '"></div><span class="legend-count">' + item.count + '</span> ' + item.label + '</div>';
  });
  svg.innerHTML += '<text x="18" y="19" text-anchor="middle" fill="#323130" font-size="6" font-weight="600" font-family="Segoe UI,sans-serif">' + total + '</text><text x="18" y="22.5" text-anchor="middle" fill="#a19f9d" font-size="2.5" font-family="Segoe UI,sans-serif">failures</text>';
})();

// --- Category bars ---
(function() {
  const bars = document.getElementById('cat-bars');
  const cc = SCAN_DATA.category_counts;
  const entries = Object.entries(cc).sort((a, b) => b[1] - a[1]);
  const max = entries.length > 0 ? entries[0][1] : 1;
  const catColors = { ca: '#d13438', app: '#ca5010', sp: '#8764b8', role: '#005a9e', user: '#0078d4', org: '#107c10', auth: '#008272', agent: '#986f0b' };
  entries.forEach(([cat, count]) => {
    const pct = Math.max((count / max) * 100, 10);
    const color = catColors[cat] || '#8a8886';
    bars.innerHTML += '<div class="bar-row"><div class="bar-label">' + cat + '</div><div class="bar-track"><div class="bar-fill" style="width:' + pct + '%;background:' + color + '">' + count + '</div></div></div>';
  });
  if (entries.length === 0) bars.innerHTML = '<div style="color:#a19f9d;font-size:0.8125rem;padding:1rem 0">No failures detected</div>';
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
    html += '<td style="font-family:\\'Consolas\\',\\'Courier New\\',monospace;font-size:0.75rem;color:var(--text-secondary)">' + esc(f.check_id) + '</td>';
    html += '<td>' + esc(f.title);
    if (sg === 'SKIP' && f.description) html += '<div style="font-size:0.75rem;color:var(--text-light);margin-top:2px">' + esc(f.description) + '</div>';
    html += '</td>';
    html += '<td style="color:var(--text-light);font-size:0.75rem">' + esc(f.resource_id) + '</td>';
    html += '</tr>';
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

document.querySelectorAll('.findings-table th[data-sort]').forEach(th => {
  th.addEventListener('click', () => {
    const key = th.dataset.sort;
    if (sortKey === key) sortAsc = !sortAsc;
    else { sortKey = key; sortAsc = true; }
    renderFindings();
  });
});

document.getElementById('filter-status').addEventListener('change', renderFindings);
document.getElementById('filter-sev').addEventListener('change', renderFindings);
document.getElementById('filter-search').addEventListener('input', renderFindings);

// --- Tab switching ---
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
  });
});

renderFindings();
</script>
</body>
</html>
"""
