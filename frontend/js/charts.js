/* SecureGate AI — Chart.js helpers (Section 10.3). Requires Chart.js 4.x
   loaded via CDN before this script. */

(function () {
  const PALETTE = {
    dns: "#3fb2ff",
    tcp: "#2ecc71",
    icmp: "#f5a623",
    other: "#7a8ca3",
    low: "#2ecc71",
    medium: "#f5a623",
    high: "#e5484d",
    grid: "rgba(255,255,255,0.06)",
    text: "#9fb3c8",
  };

  Chart.defaults.color = PALETTE.text;
  Chart.defaults.borderColor = PALETTE.grid;
  Chart.defaults.font.family = "Segoe UI, Inter, sans-serif";

  function destroyIfExists(canvas) {
    const existing = Chart.getChart(canvas);
    if (existing) existing.destroy();
  }

  function protocolDonut(canvasId, dataByProtocol) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return null;
    destroyIfExists(canvas);

    const labels = Object.keys(dataByProtocol);
    const values = Object.values(dataByProtocol);
    const colors = labels.map((l) => PALETTE[l.toLowerCase()] || PALETTE.other);

    return new Chart(canvas, {
      type: "doughnut",
      data: { labels, datasets: [{ data: values, backgroundColor: colors, borderWidth: 0 }] },
      options: {
        cutout: "68%",
        hoverOffset: 6,
        plugins: { legend: { position: "bottom" } },
        responsive: true,
        maintainAspectRatio: false,
      },
    });
  }

  function riskDonut(canvasId, { low = 0, medium = 0, high = 0 } = {}) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return null;
    destroyIfExists(canvas);

    return new Chart(canvas, {
      type: "doughnut",
      data: {
        labels: ["Low", "Medium", "High"],
        datasets: [{ data: [low, medium, high], backgroundColor: [PALETTE.low, PALETTE.medium, PALETTE.high], borderWidth: 0 }],
      },
      options: {
        cutout: "68%",
        hoverOffset: 6,
        plugins: { legend: { position: "bottom" } },
        responsive: true,
        maintainAspectRatio: false,
      },
    });
  }

  function hourlyLine(canvasId, hourlyData) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return null;
    destroyIfExists(canvas);

    const hours = Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2, "0")}:00`);
    const counts = Array.from({ length: 24 }, (_, i) => {
      const entry = Array.isArray(hourlyData)
        ? hourlyData.find((r) => Number(r.hour) === i)
        : { count: hourlyData[String(i)] };
      return entry ? Number(entry.count || 0) : 0;
    });

    return new Chart(canvas, {
      type: "line",
      data: {
        labels: hours,
        datasets: [{
          label: "Events",
          data: counts,
          borderColor: PALETTE.dns,
          backgroundColor: "rgba(63,178,255,0.15)",
          tension: 0.4,
          fill: true,
          pointRadius: 3,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true } },
      },
    });
  }

  function weeklyStackedBar(canvasId, dailySummaries) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return null;
    destroyIfExists(canvas);

    const sorted = [...dailySummaries].sort((a, b) => new Date(a.summary_date) - new Date(b.summary_date));
    const labels = sorted.map((d) => new Date(d.summary_date).toLocaleDateString(undefined, { month: "short", day: "numeric" }));

    return new Chart(canvas, {
      type: "bar",
      data: {
        labels,
        datasets: [
          { label: "DNS", data: sorted.map((d) => d.dns_events || 0), backgroundColor: PALETTE.dns },
          { label: "TCP", data: sorted.map((d) => d.tcp_events || 0), backgroundColor: PALETTE.tcp },
          { label: "ICMP", data: sorted.map((d) => d.icmp_events || 0), backgroundColor: PALETTE.icmp },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: "bottom" } },
        scales: {
          x: { stacked: true },
          y: { stacked: true, beginAtZero: true },
        },
      },
    });
  }

  function topRiskyHorizontalBar(canvasId, topDevices) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return null;
    destroyIfExists(canvas);

    const labels = topDevices.map((d) => d.source_ip);
    const values = topDevices.map((d) => Number(d.avg_risk_score || 0));

    return new Chart(canvas, {
      type: "bar",
      data: {
        labels,
        datasets: [{
          label: "Avg Risk Score",
          data: values,
          backgroundColor: values.map((v) => (v > 60 ? PALETTE.high : v > 30 ? PALETTE.medium : PALETTE.low)),
        }],
      },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { x: { beginAtZero: true, max: 100 } },
      },
    });
  }

  window.SecureGateCharts = {
    protocolDonut,
    riskDonut,
    hourlyLine,
    weeklyStackedBar,
    topRiskyHorizontalBar,
  };
})();
