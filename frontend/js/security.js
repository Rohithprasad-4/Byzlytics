/* SecureGate AI — Security Analytics page logic. */

(function () {
  const { api, formatDateTime, riskBadge, truncate, explanationText, showToast, startAutoRefresh } = window.SecureGateAPI;
  const { riskDonut, topRiskyHorizontalBar } = window.SecureGateCharts;

  function renderExplanations(risks) {
    const body = document.getElementById("explanations-body");
    if (!risks || risks.length === 0) {
      body.innerHTML = '<tr><td colspan="4" class="empty-state">No risk assessments yet. Click "Run Assessment".</td></tr>';
      return;
    }
    body.innerHTML = risks
      .slice(0, 20)
      .map((r) => `
        <tr>
          <td class="mono">${r.source_ip || "—"}</td>
          <td>${riskBadge(r.risk_category)} ${Number(r.risk_score || 0).toFixed(1)}</td>
          <td>${truncate(explanationText(r.explanation), 140)}</td>
          <td>${formatDateTime(r.assessed_at)}</td>
        </tr>`)
      .join("");
  }

  function renderActiveDecisions(decisions) {
    const body = document.getElementById("active-decisions-body");
    if (!decisions || decisions.length === 0) {
      body.innerHTML = '<tr><td colspan="4" class="empty-state">No active decisions.</td></tr>';
      return;
    }
    body.innerHTML = decisions
      .map((d) => `
        <tr>
          <td class="mono">${d.ip_address}</td>
          <td>${riskBadge(d.action)}</td>
          <td>${d.reason || "—"}</td>
          <td>${formatDateTime(d.decided_at)}</td>
        </tr>`)
      .join("");
  }

  async function loadSecurity() {
    try {
      const [risksResp, topRisks, decisions] = await Promise.all([
        api.getRisks("?limit=50"),
        api.getTopRisks(8),
        api.getDecisions("?limit=50"),
      ]);

      const items = risksResp.items || [];
      const low = items.filter((r) => r.risk_category === "Low").length;
      const medium = items.filter((r) => r.risk_category === "Medium").length;
      const high = items.filter((r) => r.risk_category === "High").length;
      const avg = items.length ? items.reduce((sum, r) => sum + Number(r.risk_score || 0), 0) / items.length : 0;

      document.getElementById("kpi-high").textContent = high;
      document.getElementById("kpi-medium").textContent = medium;
      document.getElementById("kpi-low").textContent = low;
      document.getElementById("kpi-avg").textContent = avg.toFixed(1);

      riskDonut("chart-risk-donut", { low, medium, high });
      topRiskyHorizontalBar("chart-top-risky", topRisks || []);

      renderExplanations(items);
      renderActiveDecisions(decisions.items || []);
    } catch (err) {
      showToast(err.message || "Failed to load security data", "error");
    }
  }

  document.getElementById("run-assessment-btn").addEventListener("click", async (event) => {
    event.preventDefault();
    const button = event.target;
    button.disabled = true;
    button.textContent = "Running…";
    try {
      const result = await api.runAssessment({ limit: 200, use_gpt: false });
      showToast(`Assessed ${result.assessed ?? 0} event(s)`, "success");
      loadSecurity();
    } catch (err) {
      showToast(err.message || "Assessment failed", "error");
    } finally {
      button.disabled = false;
      button.textContent = "Run Assessment";
    }
  });

  document.getElementById("download-report-btn").addEventListener("click", (event) => {
    event.preventDefault();
    window.open(api.downloadReportUrl(), "_blank");
  });

  startAutoRefresh(loadSecurity);
})();
