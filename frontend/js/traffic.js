/* SecureGate AI — Traffic Analytics page logic. */

(function () {
  const { api, formatDateTime, protocolBadge, showToast, startAutoRefresh } = window.SecureGateAPI;
  const { protocolDonut, hourlyLine, weeklyStackedBar } = window.SecureGateCharts;

  function renderEvents(events) {
    const body = document.getElementById("events-body");
    if (!events || events.length === 0) {
      body.innerHTML = '<tr><td colspan="5" class="empty-state">No events captured yet.</td></tr>';
      return;
    }
    body.innerHTML = events
      .slice(0, 25)
      .map((e) => `
        <tr>
          <td>${formatDateTime(e.timestamp)}</td>
          <td>${protocolBadge(e.protocol)}</td>
          <td class="mono">${e.source_ip}${e.source_port ? ":" + e.source_port : ""}</td>
          <td class="mono">${e.destination_ip}${e.destination_port ? ":" + e.destination_port : ""}</td>
          <td>${e.processed ? "Scored" : "Pending"}</td>
        </tr>`)
      .join("");
  }

  async function loadTraffic() {
    try {
      const [protocolDist, hourly, events, summary] = await Promise.all([
        api.getEventsByProtocol(),
        api.getEventsHourly(),
        api.getEvents("?limit=25"),
        api.getSummary(7),
      ]);

      const protocolMap = {};
      (protocolDist || []).forEach((row) => { protocolMap[row.protocol] = Number(row.count); });
      protocolDonut("chart-protocol", Object.keys(protocolMap).length ? protocolMap : { DNS: 0, TCP: 0, ICMP: 0 });

      hourlyLine("chart-hourly", hourly || []);

      if (summary && summary.length) {
        weeklyStackedBar("chart-weekly", summary);
      }

      renderEvents(events.items || []);
    } catch (err) {
      showToast(err.message || "Failed to load traffic data", "error");
    }
  }

  startAutoRefresh(loadTraffic);
})();
