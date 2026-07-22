/* SecureGate AI — central API client (Section 10.1).
   All fetch() calls live here; pages import shared utilities via
   window.SecureGateAPI so no build step / module bundler is needed. */

(function () {
  const API_BASE = window.SECUREGATE_API_BASE || "http://localhost:5000";
  const REFRESH_INTERVAL_MS = 30000;

  async function request(path, { method = "GET", body } = {}) {
    const response = await fetch(`${API_BASE}${path}`, {
      method,
      headers: { "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || payload.status === "error") {
      throw new Error(payload.message || `Request failed (${response.status})`);
    }
    return payload.data;
  }

  const api = {
    health: () => request("/health"),

    getDevices: (params = "") => request(`/devices${params}`),
    getDeviceStats: () => request("/devices/stats"),
    getDeviceByIp: (ip) => request(`/devices/lookup/${ip}`),

    getEvents: (params = "") => request(`/events${params}`),
    getEventsByProtocol: () => request("/events/protocols"),
    getEventsHourly: () => request("/events/hourly"),

    getRisks: (params = "") => request(`/risks${params}`),
    getTopRisks: (limit = 10) => request(`/risks/top?limit=${limit}`),

    getStats: () => request("/stats"),
    getSummary: (days = 7) => request(`/summary?days=${days}`),
    generateSummary: (date) => request("/summary/generate", { method: "POST", body: date ? { date } : {} }),

    getDecisions: (params = "") => request(`/decisions${params}`),
    getDecisionHistory: (params = "") => request(`/decisions/history${params}`),
    getDecisionSummary: () => request("/decisions/summary"),
    decide: (payload) => request("/decide", { method: "POST", body: payload }),
    revoke: (ip) => request(`/revoke/${ip}`, { method: "POST" }),
    checkBlocked: (ip) => request(`/check/${ip}`),

    runAssessment: (payload = {}) => request("/assess", { method: "POST", body: payload }),

    listReports: () => request("/report/list"),
    generateReport: (date) => request("/report/generate", { method: "POST", body: date ? { date } : {} }),
    downloadReportUrl: (date) => `${API_BASE}/report/download${date ? `?date=${date}` : ""}`,
  };

  // ---------- Shared formatting helpers ----------

  function formatIP(ip) {
    return ip || "—";
  }

  function formatDateTime(value) {
    if (!value) return "—";
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return String(value);
    return d.toLocaleString(undefined, {
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
    });
  }

  function riskBadge(category) {
    if (!category) return '<span class="badge other">Unknown</span>';
    const cls = category.toLowerCase();
    return `<span class="badge ${cls}">${category}</span>`;
  }

  function protocolBadge(protocol) {
    const cls = (protocol || "other").toLowerCase();
    return `<span class="badge ${cls}">${protocol || "OTHER"}</span>`;
  }

  function statusBadge(device) {
    if (device.is_blocked) return '<span class="badge blocked">Blocked</span>';
    if (device.is_trusted) return '<span class="badge trusted">Trusted</span>';
    return '<span class="badge other">Active</span>';
  }

  function decisionButtons(ip, { compact = false } = {}) {
    const label = (text) => (compact ? text[0] : text);
    return `
      <div class="btn-group" data-ip="${ip}">
        <button class="btn allow" data-action="allow" data-ip="${ip}">${label("Allow")}</button>
        <button class="btn block" data-action="block" data-ip="${ip}">${label("Block")}</button>
        <button class="btn always_allow" data-action="always_allow" data-ip="${ip}">${label("Always Allow")}</button>
        <button class="btn always_block" data-action="always_block" data-ip="${ip}">${label("Always Block")}</button>
      </div>`;
  }

  function truncate(text, max = 140) {
    if (!text) return "";
    return text.length > max ? `${text.slice(0, max)}…` : text;
  }

  function explanationText(explanation) {
    if (!explanation) return "No AI explanation available.";
    if (typeof explanation === "string") return explanation;
    const parts = [explanation.observation, explanation.context, explanation.recommendation].filter(Boolean);
    return parts.join(" ");
  }

  // ---------- Toast notifications ----------

  function ensureToastContainer() {
    let container = document.getElementById("toast-container");
    if (!container) {
      container = document.createElement("div");
      container.id = "toast-container";
      document.body.appendChild(container);
    }
    return container;
  }

  function showToast(message, type = "success") {
    const container = ensureToastContainer();
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
  }

  // ---------- Decision action wiring (shared across pages) ----------

  async function handleDecisionClick(event) {
    const button = event.target.closest("button[data-action]");
    if (!button) return;
    const action = button.dataset.action;
    const ip = button.dataset.ip;
    if (!ip) return;

    button.disabled = true;
    try {
      await api.decide({ ip_address: ip, action });
      showToast(`${action.replace("_", " ")} recorded for ${ip}`, "success");
      document.dispatchEvent(new CustomEvent("securegate:refresh"));
    } catch (err) {
      showToast(err.message || "Action failed", "error");
    } finally {
      button.disabled = false;
    }
  }

  document.addEventListener("click", handleDecisionClick);

  // ---------- Auto-refresh ----------

  function startAutoRefresh(callback) {
    callback();
    const interval = setInterval(callback, REFRESH_INTERVAL_MS);
    document.addEventListener("securegate:refresh", callback);
    return () => clearInterval(interval);
  }

  window.SecureGateAPI = {
    api,
    formatIP,
    formatDateTime,
    riskBadge,
    protocolBadge,
    statusBadge,
    decisionButtons,
    truncate,
    explanationText,
    showToast,
    startAutoRefresh,
  };
})();
