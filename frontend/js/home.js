/* SecureGate AI — Home / Overview page logic. */

(function () {
  const { api, riskBadge, decisionButtons, showToast, startAutoRefresh } = window.SecureGateAPI;
  const { protocolDonut, hourlyLine, weeklyStackedBar } = window.SecureGateCharts;

  function renderSuspiciousDevices(devices) {
    const body = document.getElementById("suspicious-devices-body");
    if (!devices || devices.length === 0) {
      body.innerHTML = '<tr><td colspan="4" class="empty-state">No suspicious devices detected.</td></tr>';
      return;
    }
    body.innerHTML = devices
      .slice(0, 8)
      .map((d) => {
        const score = Number(d.avg_risk_score || 0);
        const category = score > 60 ? "High" : score > 30 ? "Medium" : "Low";
        return `<tr>
          <td class="mono">${d.source_ip}</td>
          <td>${riskBadge(category)} ${score.toFixed(1)}</td>
          <td>${d.event_count}</td>
          <td>${decisionButtons(d.source_ip, { compact: true })}</td>
        </tr>`;
      })
      .join("");
  }

  async function loadOverview() {
    try {
      const [stats, topRisks, summary] = await Promise.all([
        api.getStats(),
        api.getTopRisks(8),
        api.getSummary(7),
      ]);

      const live = stats.live || {};
      const devices = live.devices || {};
      const risks = live.risks || stats;

      document.getElementById("kpi-devices").textContent = devices.total_devices ?? stats.total_devices ?? 0;
      document.getElementById("kpi-trusted").textContent = devices.trusted_devices ?? 0;
      document.getElementById("kpi-blocked").textContent = devices.blocked_devices ?? stats.blocked_devices ?? 0;
      document.getElementById("kpi-high-risk").textContent =
        risks.high_risk_count ?? stats.high_risk_count ?? 0;

      const protocolDist = live.protocol_distribution || stats.protocol_distribution || {};
      protocolDonut("chart-protocol", Object.keys(protocolDist).length ? protocolDist : { DNS: 0, TCP: 0, ICMP: 0 });

      hourlyLine("chart-hourly", live.hourly_distribution || stats.hourly_distribution || {});

      if (summary && summary.length) {
        weeklyStackedBar("chart-weekly", summary);
      }

      renderSuspiciousDevices(topRisks);
    } catch (err) {
      showToast(err.message || "Failed to load overview data", "error");
    }
  }

  startAutoRefresh(loadOverview);
})();
