/* Local Chart.js, text-only DOM updates, and one request at a time. */
(() => {
  "use strict";
  const initial = JSON.parse(document.getElementById("dashboard-data").textContent);
  const status = document.getElementById("refresh-status");
  const button = document.getElementById("pause-live");
  let paused = false;
  let pending = false;
  let stopped = false;
  const charts = {};
  const colors = ["#72e3bf", "#83b5ff", "#ffc17d", "#e3a8ef"];
  const timeLabel = text => new Date(text).toLocaleString("en-GB", {timeZone: "UTC", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit"});
  if (window.Chart) {
    Chart.defaults.color = "#a5b5ca";
    Chart.defaults.borderColor = "#29374b";
    const options = {responsive: true, maintainAspectRatio: false, animation: false,
      plugins: {legend: {display: false}}, scales: {x: {grid: {display: false}, ticks: {maxTicksLimit: 6}}, y: {beginAtZero: true, ticks: {precision: 0}}}};
    charts.events = new Chart(document.getElementById("events-chart"), {type: "bar", data: {labels: [], datasets: [{label: "Application events", data: [], backgroundColor: colors[0], borderRadius: 3}]}, options});
    charts.risk = new Chart(document.getElementById("risk-chart"), {type: "line", data: {labels: [], datasets: [{label: "Highest entity risk", data: [], borderColor: colors[1], pointRadius: 2, stepped: true}]}, options: {...options, scales: {...options.scales, y: {...options.scales.y, max: 100}}}});
    charts.threats = new Chart(document.getElementById("threat-chart"), {type: "bar", data: {labels: [], datasets: [{label: "Findings", data: [], backgroundColor: colors, borderRadius: 3}]}, options: {...options, indexAxis: "y", scales: {x: {beginAtZero: true, ticks: {precision: 0}}, y: {grid: {display: false}}}}});
  }
  function table(id, rows) {
    const body = document.getElementById(id);
    body.replaceChildren(...rows.map(values => {
      const row = document.createElement("tr");
      values.forEach(value => {const cell = document.createElement("td"); cell.textContent = value; row.append(cell);});
      return row;
    }));
  }
  function list(id, records, block) {
    const box = document.getElementById(id);
    if (!records.length) {const p = document.createElement("p"); p.className = "empty"; p.textContent = block ? "No active restrictions." : "No alerts in this window."; box.replaceChildren(p); return;}
    box.replaceChildren(...records.map(item => {
      const link = document.createElement("a"); link.href = `/admin/entities/${Number(item.entity_id)}`;
      const badge = document.createElement("span"); badge.className = "badge warning"; badge.textContent = block ? "BLOCKED" : item.severity.toUpperCase();
      const name = document.createElement("strong"); name.textContent = item.entity_key;
      const reason = document.createElement("span"); reason.textContent = block ? `Expires ${timeLabel(item.expires_at)} UTC` : item.reason;
      link.append(badge, name, reason); return link;
    }));
  }
  function render(data) {
    Object.entries(data.metrics).forEach(([key, value]) => {document.getElementById(`metric-${key}`).textContent = value.toLocaleString();});
    if (charts.events) {
      for (const name of ["events", "risk"]) {charts[name].data.labels = data.series.labels.map(timeLabel); charts[name].data.datasets[0].data = data.series[name]; charts[name].update("none");}
      charts.threats.data.labels = data.threats.map(item => item.label); charts.threats.data.datasets[0].data = data.threats.map(item => item.count); charts.threats.update("none");
    }
    table("series-data", data.series.labels.map((label, i) => [timeLabel(label) + " UTC", data.series.events[i], data.series.risk[i]]));
    table("threat-data", data.threats.map(item => [item.label, item.count]));
    list("alert-list", data.alerts, false); list("block-list", data.blocks, true);
    status.textContent = `Updated ${timeLabel(data.as_of)} UTC · ${charts.events ? "Live every 5 seconds" : "Charts unavailable; data tables available"}`;
  }
  async function refresh() {
    if (paused || pending || stopped || document.hidden) return;
    pending = true;
    try {
      const response = await fetch(`/api/dashboard?hours=${initial.hours}`, {headers: {Accept: "application/json"}, signal: AbortSignal.timeout(10000)});
      if ([401, 403, 429].includes(response.status)) {stopped = true; throw new Error("Access changed. Reload or sign in again.");}
      if (!response.ok) throw new Error("Refresh failed. Showing the last successful snapshot.");
      render(await response.json());
    } catch (error) {status.textContent = error.message || "Refresh failed; retrying shortly.";} finally {pending = false;}
  }
  button.addEventListener("click", () => {paused = !paused; button.textContent = paused ? "Resume updates" : "Pause updates"; if (paused) status.textContent = "Updates paused. Displayed data is a snapshot."; else refresh();});
  document.addEventListener("visibilitychange", () => {if (!document.hidden) refresh();});
  render(initial);
  setInterval(refresh, 5000);
})();
