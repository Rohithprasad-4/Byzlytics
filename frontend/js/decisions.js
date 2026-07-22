/* SecureGate AI — Decision Management page logic. */

(function () {
  const { api, formatDateTime, riskBadge, showToast, startAutoRefresh } = window.SecureGateAPI;

  function renderActiveDecisions(decisions) {
    const body = document.getElementById("active-decisions-body");
    if (!decisions || decisions.length === 0) {
      body.innerHTML = '<tr><td colspan="5" class="empty-state">No active decisions.</td></tr>';
      return;
    }
    body.innerHTML = decisions
      .map((d) => `
        <tr>
          <td class="mono">${d.ip_address}</td>
          <td>${riskBadge(d.action)}</td>
          <td>${d.reason || "—"}</td>
          <td>${formatDateTime(d.decided_at)}</td>
          <td><button class="btn revoke" data-revoke="${d.ip_address}">Revoke</button></td>
        </tr>`)
      .join("");
  }

  function renderHistory(history) {
    const body = document.getElementById("history-body");
    if (!history || history.length === 0) {
      body.innerHTML = '<tr><td colspan="5" class="empty-state">No decision history.</td></tr>';
      return;
    }
    body.innerHTML = history
      .map((d) => `
        <tr class="${d.is_active ? "" : "inactive-row"}">
          <td class="mono">${d.ip_address}</td>
          <td>${riskBadge(d.action)}</td>
          <td>${d.reason || "—"}</td>
          <td>${formatDateTime(d.decided_at)}</td>
          <td>${d.is_active ? '<span class="badge active">Active</span>' : "Inactive"}</td>
        </tr>`)
      .join("");
  }

  async function loadDecisions() {
    try {
      const [summary, active, history] = await Promise.all([
        api.getDecisionSummary(),
        api.getDecisions("?limit=100"),
        api.getDecisionHistory("?limit=100"),
      ]);

      document.getElementById("kpi-always-allow").textContent = summary.always_allow_count ?? 0;
      document.getElementById("kpi-always-block").textContent = summary.always_block_count ?? 0;
      document.getElementById("kpi-active").textContent = summary.active_count ?? 0;
      document.getElementById("kpi-total").textContent = summary.total ?? 0;

      renderActiveDecisions(active.items || []);
      renderHistory(history || []);
    } catch (err) {
      showToast(err.message || "Failed to load decisions", "error");
    }
  }

  document.getElementById("decision-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const ip = document.getElementById("form-ip").value.trim();
    const action = document.getElementById("form-action").value;
    const reason = document.getElementById("form-reason").value.trim();

    try {
      await api.decide({ ip_address: ip, action, reason: reason || undefined });
      showToast(`${action} recorded for ${ip}`, "success");
      document.getElementById("decision-form").reset();
      loadDecisions();
    } catch (err) {
      showToast(err.message || "Failed to record decision", "error");
    }
  });

  document.getElementById("history-filter-btn").addEventListener("click", async () => {
    const ip = document.getElementById("history-ip-filter").value.trim();
    try {
      const history = await api.getDecisionHistory(ip ? `?ip=${encodeURIComponent(ip)}&limit=100` : "?limit=100");
      renderHistory(history || []);
    } catch (err) {
      showToast(err.message || "Failed to filter history", "error");
    }
  });

  document.addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-revoke]");
    if (!button) return;
    const ip = button.dataset.revoke;
    button.disabled = true;
    try {
      await api.revoke(ip);
      showToast(`Revoked all decisions for ${ip}`, "success");
      loadDecisions();
    } catch (err) {
      showToast(err.message || "Revoke failed", "error");
    } finally {
      button.disabled = false;
    }
  });

  startAutoRefresh(loadDecisions);
})();
