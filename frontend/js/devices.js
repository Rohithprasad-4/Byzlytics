/* SecureGate AI — Device Analytics page logic. */

(function () {
  const { api, formatDateTime, statusBadge, decisionButtons, showToast, startAutoRefresh } = window.SecureGateAPI;

  function renderDevices(devices) {
    const body = document.getElementById("devices-body");
    if (!devices || devices.length === 0) {
      body.innerHTML = '<tr><td colspan="7" class="empty-state">No devices discovered yet. Start capture to populate this table.</td></tr>';
      return;
    }
    body.innerHTML = devices
      .map((d) => `
        <tr>
          <td class="mono">${d.ip_address}</td>
          <td class="mono">${d.mac_address || "—"}</td>
          <td>${d.device_type || "unknown"}</td>
          <td>${formatDateTime(d.first_seen)}</td>
          <td>${formatDateTime(d.last_seen)}</td>
          <td>${statusBadge(d)}</td>
          <td>${decisionButtons(d.ip_address, { compact: true })}</td>
        </tr>`)
      .join("");
  }

  async function loadDevices() {
    try {
      const [stats, deviceList] = await Promise.all([
        api.getDeviceStats(),
        api.getDevices("?limit=100"),
      ]);

      document.getElementById("kpi-total").textContent = stats.total_devices ?? 0;
      document.getElementById("kpi-trusted").textContent = stats.trusted_devices ?? 0;
      document.getElementById("kpi-blocked").textContent = stats.blocked_devices ?? 0;
      document.getElementById("kpi-new-today").textContent = stats.new_today ?? 0;

      renderDevices(deviceList.items || []);
    } catch (err) {
      showToast(err.message || "Failed to load devices", "error");
    }
  }

  startAutoRefresh(loadDevices);
})();
