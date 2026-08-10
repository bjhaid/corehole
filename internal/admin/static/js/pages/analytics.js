import {initAdminPage} from "../admin.js";
import {fetchJSON, fetchOptionalJSON} from "../lib/api.js";
import {on, required} from "../lib/dom.js";
import {cloneTemplate, configureTemplates, emptyRow, setTemplateText, templateField} from "../lib/elements.js";
import {analyticsCount, analyticsTotalQueryCount, countValue, normalizeAnalyticsItems} from "../lib/analytics-summary.js";
import {displayNumber, displayValue, firstDefined, formatTime, pick} from "../lib/format.js";

const clientSeriesColors = ["#276ef1", "#179c5f", "#d64545", "#8a63d2", "#d08b13", "#0f8a9d"];
const retentionUnits = Object.freeze({
  seconds: 1,
  minutes: 60,
  hours: 60 * 60,
  days: 24 * 60 * 60
});

function fields() {
  return {
    status: required("#analytics-status"),
    form: required("#analytics-settings-form"),
    privacyLevel: required("#privacy-level"),
    retentionValue: required("#retention-value"),
    retentionUnit: required("#retention-unit"),
    save: required("#analytics-save"),
    cleanup: required("#analytics-cleanup"),
    message: required("#analytics-message"),
    privacyNote: required("#privacy-note"),
    retentionNote: required("#retention-note"),
    blockedClientCount: required("#analytics-blocked-client-count"),
    blockedClientsBody: required("#analytics-blocked-clients-body"),
    bucketCount: required("#analytics-bucket-count"),
    bucketsChart: required("#analytics-buckets-chart"),
    bucketsTitle: required("#analytics-buckets-title"),
    bucketsChartBody: required("#analytics-buckets-chart-body"),
    bucketsTooltip: required("#analytics-buckets-tooltip"),
    queriedCount: required("#analytics-queried-count"),
    queriedBody: required("#analytics-queried-body"),
    blockedCount: required("#analytics-blocked-count"),
    blockedBody: required("#analytics-blocked-body"),
    clientCount: required("#analytics-client-count"),
    clientsBody: required("#analytics-clients-body"),
    clientActivityCount: required("#analytics-client-activity-count"),
    clientActivityChart: required("#analytics-client-activity-chart"),
    clientActivityTitle: required("#analytics-client-activity-title"),
    clientActivityLegend: required("#analytics-client-activity-legend"),
    clientActivityBody: required("#analytics-client-activity-body"),
    clientActivityTooltip: required("#analytics-client-activity-tooltip")
  };
}

function hiddenLabel(value, fallback) {
  if (value === "") {
    return fallback;
  }
  return displayValue(value);
}

function privacyDescription(level) {
  switch (Number(level)) {
  case 0:
    return "Level 0 stores and shows client IPs and queried domains.";
  case 1:
    return "Level 1 hides client IPs while retaining queried domains.";
  case 2:
    return "Level 2 hides client IPs and queried domains.";
  default:
    return "Privacy level not reported by backend.";
  }
}

function formatPercent(value) {
  if (!Number.isFinite(value) || value <= 0) {
    return "0%";
  }
  if (value < 0.1) {
    return "<0.1%";
  }
  return value.toFixed(value >= 10 ? 0 : 1) + "%";
}

function retentionDisplayValue(seconds) {
  const normalized = Number(seconds);
  if (!Number.isFinite(normalized) || normalized <= 0) {
    return {value: 0, unit: "seconds"};
  }
  for (const unit of ["days", "hours", "minutes"]) {
    const factor = retentionUnits[unit];
    if (normalized % factor === 0) {
      return {value: normalized / factor, unit};
    }
  }
  return {value: normalized, unit: "seconds"};
}

function retentionSeconds(value, unit) {
  const numeric = Number(value);
  const factor = retentionUnits[unit] || retentionUnits.seconds;
  if (!Number.isFinite(numeric) || numeric < 0) {
    return undefined;
  }
  return Math.floor(numeric * factor);
}

function retentionUnitLabel(unit) {
  switch (unit) {
  case "days":
    return "days";
  case "hours":
    return "hours";
  case "minutes":
    return "minutes";
  default:
    return "seconds";
  }
}

function setFrequency(row, count, denominator, fallbackUsed) {
  const frequencyCell = row.querySelector(".frequency-cell");
  const fill = templateField(row, "frequency-fill");
  const label = templateField(row, "frequency-label");
  const percent = denominator > 0 ? Math.min(100, (count / denominator) * 100) : 0;
  fill.style.width = percent.toFixed(2) + "%";
  label.textContent = formatPercent(percent);
  if (fallbackUsed) {
    frequencyCell.title = "Total query count is unavailable; frequency is scaled against the highest visible count.";
  } else {
    frequencyCell.title = displayNumber(count) + " of " + displayNumber(denominator) + " total queries.";
  }
}

function analyticsClientName(row) {
  return hiddenLabel(firstDefined(row, ["client_ip", "clientIP", "client", "name", "ip", "address"]), "(hidden by privacy)");
}

function renderAnalyticsPairTable(body, countField, rows, firstHeader, emptyText, hiddenText, namePaths, showFrequency, frequencyDenominator) {
  body.textContent = "";
  countField.textContent = "";
  if (!rows.length) {
    body.appendChild(emptyRow(showFrequency ? 3 : 2, emptyText));
    return;
  }
  const fallbackDenominator = Math.max(...rows.map(analyticsCount), 1);
  const totalDenominator = countValue(frequencyDenominator);
  const denominator = totalDenominator === undefined ? fallbackDenominator : totalDenominator;
  for (const row of rows) {
    const tr = cloneTemplate(showFrequency ? "analyticsFrequencyRow" : "analyticsTotalRow");
    const name = firstDefined(row, namePaths);
    const count = analyticsCount(row);
    setTemplateText(tr, "name", hiddenLabel(name, hiddenText || firstHeader));
    setTemplateText(tr, "count", displayNumber(count));
    if (showFrequency) {
      setFrequency(tr, count, denominator, totalDenominator === undefined);
    }
    body.appendChild(tr);
  }
}

function analyticsNumber(value) {
  if (typeof value === "number" && Number.isFinite(value)) {
    return Math.max(0, value);
  }
  if (typeof value === "string" && value.trim() !== "" && !Number.isNaN(Number(value))) {
    return Math.max(0, Number(value));
  }
  return 0;
}

function bucketCount(bucket, paths) {
  return analyticsNumber(firstDefined(bucket, paths));
}

function bucketWindow(bucket) {
  const start = firstDefined(bucket, ["start", "from"]);
  const end = firstDefined(bucket, ["end", "to"]);
  return formatTime(start) + " - " + formatTime(end);
}

function bucketShortLabel(bucket) {
  const value = firstDefined(bucket, ["start", "from", "end", "to"]);
  if (!value) {
    return "Bucket";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return displayValue(value);
  }
  return date.toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"});
}

function bucketMetrics(bucket) {
  const allowed = bucketCount(bucket, ["allowed", "allow"]);
  const blocked = bucketCount(bucket, ["blocked", "block"]);
  const reportedTotal = bucketCount(bucket, ["total", "count", "queries"]);
  return {
    total: Math.max(reportedTotal, allowed + blocked),
    allowed,
    blocked
  };
}

function bucketBlockedPercent(metrics) {
  return metrics.total > 0 ? (metrics.blocked / metrics.total) * 100 : 0;
}

function bucketHasActivity(bucket) {
  return bucketMetrics(bucket).total > 0;
}

function trimLeadingEmptyBuckets(buckets) {
  const firstActivity = buckets.findIndex(bucketHasActivity);
  return firstActivity < 0 ? [] : buckets.slice(firstActivity);
}

function setBucketSegment(column, field, count, total) {
  const segment = templateField(column, field);
  if (!segment) {
    return;
  }
  if (count <= 0 || total <= 0) {
    segment.classList.add("hidden");
    segment.style.flexBasis = "0%";
    return;
  }
  segment.classList.remove("hidden");
  segment.style.flexBasis = ((count / total) * 100).toFixed(2) + "%";
}

function tooltipRows(tooltip, rows) {
  tooltip.textContent = "";
  for (const [name, value] of rows) {
    const row = document.createElement("div");
    row.className = "bucket-tooltip-row";
    const term = document.createElement("span");
    term.className = "bucket-tooltip-term";
    term.textContent = name;
    const detail = document.createElement("span");
    detail.className = "bucket-tooltip-detail";
    detail.textContent = value;
    row.append(term, detail);
    tooltip.appendChild(row);
  }
}

function positionTooltip(chart, column, tooltip, event) {
  const chartRect = chart.getBoundingClientRect();
  const columnRect = column.getBoundingClientRect();
  const tooltipRect = tooltip.getBoundingClientRect();
  const pointerX = event && Number.isFinite(event.clientX) ? event.clientX : columnRect.left + columnRect.width / 2;
  const pointerY = event && Number.isFinite(event.clientY) ? event.clientY : columnRect.top;
  const margin = 10;
  let left = pointerX - chartRect.left - tooltipRect.width / 2;
  left = Math.max(margin, Math.min(left, chartRect.width - tooltipRect.width - margin));
  let top = pointerY - chartRect.top - tooltipRect.height - margin;
  if (top < margin) {
    top = pointerY - chartRect.top + margin;
  }
  top = Math.max(margin, Math.min(top, chartRect.height - tooltipRect.height - margin));
  tooltip.style.left = left + "px";
  tooltip.style.top = top + "px";
}

function showBucketTooltip(target, column, label, metrics, event) {
  const tooltip = target.bucketsTooltip;
  tooltipRows(tooltip, [
    ["Window", label],
    ["Allowed/permitted", displayNumber(metrics.allowed)],
    ["Blocked", displayNumber(metrics.blocked)],
    ["Total", displayNumber(metrics.total)],
    ["Blocked %", formatPercent(bucketBlockedPercent(metrics))]
  ]);
  tooltip.classList.remove("hidden");
  column.setAttribute("aria-describedby", tooltip.id);
  positionTooltip(target.bucketsChart, column, tooltip, event);
}

function hideTooltip(column, tooltip) {
  tooltip.classList.add("hidden");
  tooltip.style.left = "";
  tooltip.style.top = "";
  column.removeAttribute("aria-describedby");
}

function renderBucketChart(target, buckets) {
  target.bucketsChartBody.textContent = "";
  target.bucketsTooltip.classList.add("hidden");
  if (!buckets.length) {
    target.bucketsTitle.textContent = "DNS queries by time";
    target.bucketsChart.setAttribute("aria-label", "No query activity reported for the selected period.");
    target.bucketsChartBody.className = "bucket-empty";
    target.bucketsChartBody.removeAttribute("role");
    target.bucketsChartBody.removeAttribute("aria-label");
    target.bucketsChartBody.textContent = "No query activity in this period yet.";
    return;
  }

  const metrics = buckets.map(bucketMetrics);
  const maxTotal = Math.max(...metrics.map(item => item.total), 1);
  const totalQueries = metrics.reduce((sum, item) => sum + item.total, 0);
  const chartTitle = "DNS queries by time";
  target.bucketsTitle.textContent = chartTitle;
  target.bucketsChart.setAttribute(
    "aria-label",
    chartTitle + ". " + displayNumber(totalQueries) + " total queries."
  );
  target.bucketsChartBody.className = "bucket-chart-body";
  target.bucketsChartBody.setAttribute("role", "list");
  target.bucketsChartBody.setAttribute("aria-label", "Query activity bars");

  buckets.forEach((bucket, index) => {
    const item = metrics[index];
    const other = Math.max(item.total - item.allowed - item.blocked, 0);
    const label = bucketWindow(bucket);
    const summary = label + ": " + displayNumber(item.total) + " total, " + displayNumber(item.allowed) + " allowed/permitted, " + displayNumber(item.blocked) + " blocked, " + formatPercent(bucketBlockedPercent(item)) + " blocked.";
    const column = cloneTemplate("bucketChartColumn");
    column.setAttribute("role", "listitem");
    column.tabIndex = 0;
    column.setAttribute("aria-label", summary);
    column.title = summary;
    on(column, "mouseenter", event => showBucketTooltip(target, column, label, item, event));
    on(column, "mousemove", event => showBucketTooltip(target, column, label, item, event));
    on(column, "mouseleave", () => hideTooltip(column, target.bucketsTooltip));
    on(column, "focus", event => showBucketTooltip(target, column, label, item, event));
    on(column, "blur", () => hideTooltip(column, target.bucketsTooltip));

    const bar = templateField(column, "bar");
    bar.style.height = ((item.total / maxTotal) * 100).toFixed(2) + "%";
    bar.style.minHeight = item.total > 0 ? "2px" : "";
    setBucketSegment(column, "segment-allowed", item.allowed, item.total);
    setBucketSegment(column, "segment-blocked", item.blocked, item.total);
    setBucketSegment(column, "segment-other", other, item.total);
    setTemplateText(column, "label", bucketShortLabel(bucket));

    target.bucketsChartBody.appendChild(column);
  });
}

function clientTimeBucketRows(value) {
  const rows = [];
  const appendBucket = (bucket, client) => {
    if (!bucket || typeof bucket !== "object") {
      return;
    }
    rows.push(Object.assign({}, bucket, client ? {client_ip: client} : {}));
  };
  const appendValue = (item, client) => {
    if (Array.isArray(item)) {
      item.forEach(bucket => appendBucket(bucket, client));
      return;
    }
    if (!item || typeof item !== "object") {
      return;
    }
    const nestedClients = firstDefined(item, ["clients", "client_counts", "clientCounts"]);
    if (nestedClients !== undefined) {
      const clientRows = normalizeAnalyticsItems(nestedClients, "client_ip");
      if (!clientRows.length) {
        appendBucket(item, client);
        return;
      }
      clientRows.forEach(clientRow => {
        const clientName = firstDefined(clientRow, ["client_ip", "clientIP", "client", "name", "ip", "address"]);
        const count = analyticsCount(clientRow);
        appendBucket(Object.assign({}, item, {client_ip: clientName, count: count, total: count}), client);
      });
      return;
    }
    const nestedBuckets = firstDefined(item, ["buckets", "time_buckets", "timeBuckets", "activity"]);
    const nestedClient = firstDefined(item, ["client_ip", "clientIP", "client", "name", "ip", "address"]) || client;
    if (Array.isArray(nestedBuckets)) {
      nestedBuckets.forEach(bucket => appendBucket(bucket, nestedClient));
      return;
    }
    appendBucket(item, nestedClient);
  };
  if (Array.isArray(value)) {
    value.forEach(item => appendValue(item));
  } else if (value && typeof value === "object") {
    Object.entries(value).forEach(([client, item]) => appendValue(item, client));
  }
  return rows;
}

function bucketKey(row) {
  return String(firstDefined(row, ["start", "from", "end", "to"]) || "");
}

function renderClientLegend(target, series) {
  target.clientActivityLegend.textContent = "";
  for (const item of series) {
    const legendItem = document.createElement("span");
    legendItem.className = "client-activity-legend-item";
    const swatch = document.createElement("span");
    swatch.className = "client-activity-swatch";
    swatch.style.background = item.color;
    const label = document.createElement("span");
    label.textContent = item.name;
    legendItem.append(swatch, label);
    target.clientActivityLegend.appendChild(legendItem);
  }
}

function showClientTooltip(target, column, label, bucket, series, event) {
  const rows = [["Window", label], ["Total", displayNumber(bucket.total)]];
  for (const item of series) {
    rows.push([item.name, displayNumber(bucket.clients.get(item.name) || 0)]);
  }
  tooltipRows(target.clientActivityTooltip, rows);
  target.clientActivityTooltip.classList.remove("hidden");
  column.setAttribute("aria-describedby", target.clientActivityTooltip.id);
  positionTooltip(target.clientActivityChart, column, target.clientActivityTooltip, event);
}

function renderClientActivityChart(target, rawValue) {
  target.clientActivityBody.textContent = "";
  target.clientActivityLegend.textContent = "";
  target.clientActivityTooltip.classList.add("hidden");
  target.clientActivityTitle.textContent = "Client query volume over time";
  if (rawValue === undefined) {
    target.clientActivityCount.textContent = "Unavailable";
    target.clientActivityBody.className = "bucket-empty";
    target.clientActivityBody.textContent = "Client activity by time is not reported by this backend yet.";
    target.clientActivityChart.setAttribute("aria-label", "Client activity by time is unavailable.");
    return;
  }

  const rows = clientTimeBucketRows(rawValue);
  const clientTotals = new Map();
  const bucketsByKey = new Map();
  for (const row of rows) {
    const client = analyticsClientName(row);
    const metrics = bucketMetrics(row);
    if (metrics.total <= 0) {
      continue;
    }
    clientTotals.set(client, (clientTotals.get(client) || 0) + metrics.total);
    const key = bucketKey(row);
    if (!bucketsByKey.has(key)) {
      bucketsByKey.set(key, {row, total: 0, clients: new Map()});
    }
    const bucket = bucketsByKey.get(key);
    bucket.total += metrics.total;
    bucket.clients.set(client, (bucket.clients.get(client) || 0) + metrics.total);
  }

  const series = Array.from(clientTotals.entries())
    .filter(([, total]) => total > 0)
    .sort((a, b) => b[1] - a[1])
    .slice(0, clientSeriesColors.length)
    .map(([name, total], index) => ({name, total, color: clientSeriesColors[index]}));
  const seriesNames = new Set(series.map(item => item.name));
  const buckets = Array.from(bucketsByKey.values()).filter(bucket => bucket.total > 0);

  if (!buckets.length || !series.length) {
    target.clientActivityCount.textContent = "";
    target.clientActivityBody.className = "bucket-empty";
    target.clientActivityBody.textContent = "No per-client activity in this period yet.";
    target.clientActivityChart.setAttribute("aria-label", "No per-client activity reported for the selected period.");
    return;
  }

  const maxTotal = Math.max(...buckets.map(bucket => bucket.total), 1);
  target.clientActivityTitle.textContent = "Client activity by time";
  target.clientActivityCount.textContent = "";
  target.clientActivityChart.setAttribute("aria-label", "Top client query volume across " + buckets.length + " time windows.");
  renderClientLegend(target, series);
  target.clientActivityBody.className = "client-activity-chart-body";
  target.clientActivityBody.setAttribute("role", "list");
  target.clientActivityBody.setAttribute("aria-label", "Client activity bars");

  for (const bucket of buckets) {
    const column = document.createElement("div");
    column.className = "client-activity-column";
    column.tabIndex = 0;
    column.setAttribute("role", "listitem");
    const label = bucketWindow(bucket.row);
    const summary = label + ": " + displayNumber(bucket.total) + " total queries.";
    column.setAttribute("aria-label", summary);
    column.title = summary;
    on(column, "mouseenter", event => showClientTooltip(target, column, label, bucket, series, event));
    on(column, "mousemove", event => showClientTooltip(target, column, label, bucket, series, event));
    on(column, "mouseleave", () => hideTooltip(column, target.clientActivityTooltip));
    on(column, "focus", event => showClientTooltip(target, column, label, bucket, series, event));
    on(column, "blur", () => hideTooltip(column, target.clientActivityTooltip));

    const rail = document.createElement("div");
    rail.className = "bucket-bar-rail";
    const bar = document.createElement("div");
    bar.className = "client-activity-bar";
    bar.style.height = ((bucket.total / maxTotal) * 100).toFixed(2) + "%";
    bar.style.minHeight = "2px";
    for (const item of series) {
      const count = bucket.clients.get(item.name) || 0;
      if (count <= 0 || !seriesNames.has(item.name)) {
        continue;
      }
      const segment = document.createElement("div");
      segment.className = "client-activity-segment";
      segment.style.background = item.color;
      segment.style.flexBasis = ((count / bucket.total) * 100).toFixed(2) + "%";
      bar.appendChild(segment);
    }
    rail.appendChild(bar);
    const shortLabel = document.createElement("div");
    shortLabel.className = "bucket-label";
    shortLabel.textContent = bucketShortLabel(bucket.row);
    column.append(rail, shortLabel);
    target.clientActivityBody.appendChild(column);
  }
}

function renderUnavailable(target, error) {
  target.status.textContent = "Analytics summary unavailable: " + displayValue(error);
  target.blockedClientsBody.textContent = "";
  target.bucketsTitle.textContent = "DNS queries by time";
  target.bucketsChart.setAttribute("aria-label", "Query activity is unavailable.");
  target.bucketsChartBody.className = "bucket-empty";
  target.bucketsChartBody.textContent = "Query activity is unavailable.";
  target.queriedBody.textContent = "";
  target.blockedBody.textContent = "";
  target.clientsBody.textContent = "";
  target.clientActivityBody.textContent = "";
  target.blockedClientCount.textContent = "";
  target.bucketCount.textContent = "";
  target.queriedCount.textContent = "";
  target.blockedCount.textContent = "";
  target.clientCount.textContent = "";
  target.clientActivityCount.textContent = "";
  target.blockedClientsBody.appendChild(emptyRow(3, "Top blocked clients are unavailable."));
  target.queriedBody.appendChild(emptyRow(3, "Top queried domains are unavailable."));
  target.blockedBody.appendChild(emptyRow(3, "Top blocked domains are unavailable."));
  target.clientsBody.appendChild(emptyRow(3, "Top clients are unavailable."));
  target.clientActivityBody.className = "bucket-empty";
  target.clientActivityBody.textContent = "Client activity by time is unavailable.";
}

initAdminPage({
  label: "Analytics",
  init({setUpdatedStatus}) {
    const target = fields();
    let settingsAvailable = false;
    let retentionAvailable = false;

    configureTemplates({
      emptyRow: required("#template-empty-row"),
      analyticsTotalRow: required("#template-analytics-total-row"),
      analyticsFrequencyRow: required("#template-analytics-frequency-row"),
      bucketChartColumn: required("#template-bucket-chart-column")
    });

    function setAnalyticsMessage(text, isError) {
      target.message.textContent = text || "";
      target.message.classList.toggle("error", Boolean(isError));
    }

    function renderSettings(result) {
      settingsAvailable = result.ok;
      target.save.disabled = !settingsAvailable;
      target.cleanup.disabled = !settingsAvailable;
      target.form.querySelectorAll("select, input").forEach(element => {
        element.disabled = !settingsAvailable;
      });
      if (!result.ok) {
        target.privacyNote.textContent = "Privacy settings unavailable: " + displayValue(result.error);
        target.retentionNote.textContent = "Retention settings unavailable.";
        return;
      }

      const data = result.data || {};
      const level = firstDefined(data, ["privacy_level", "privacyLevel"]);
      if (level !== undefined && ["0", "1", "2"].includes(String(level))) {
        target.privacyLevel.value = String(level);
      }
      target.privacyNote.textContent = privacyDescription(target.privacyLevel.value);

      const retention = firstDefined(data, [
        "retention_duration_seconds",
        "retentionDurationSeconds",
        "retention_seconds",
        "retentionSeconds"
      ]);
      retentionAvailable = retention !== undefined;
      target.retentionValue.disabled = !retentionAvailable;
      target.retentionUnit.disabled = !retentionAvailable;
      if (retentionAvailable) {
        const display = retentionDisplayValue(retention);
        target.retentionValue.value = String(display.value);
        target.retentionUnit.value = display.unit;
        target.retentionNote.textContent = Number(retention) > 0
          ? "Automatic cleanup removes analytics older than " + displayNumber(display.value) + " " + retentionUnitLabel(display.unit) + "."
          : "0 disables automatic retention cleanup; manual cleanup remains available.";
      } else {
        target.retentionValue.value = "";
        target.retentionNote.textContent = "Retention duration is not reported by this backend.";
      }
    }

    function renderSummary(result) {
      if (!result.ok) {
        renderUnavailable(target, result.error);
        return;
      }

      const data = result.data || {};
      target.status.textContent = "Analytics loaded";
      const totalQueryCount = analyticsTotalQueryCount(data);

      const blockedClientsValue = pick(data, ["top_blocked_clients", "topBlockedClients", "blocked_clients", "blockedClients"]);
      renderAnalyticsPairTable(
        target.blockedClientsBody,
        target.blockedClientCount,
        normalizeAnalyticsItems(blockedClientsValue, "client_ip"),
        "Client",
        blockedClientsValue === undefined ? "Top blocked clients are not reported by this backend yet." : "No top blocked clients reported.",
        "(hidden by privacy)",
        ["client_ip", "clientIP", "client", "name", "ip", "address"],
        true,
        totalQueryCount
      );
      if (blockedClientsValue === undefined) {
        target.blockedClientCount.textContent = "Unavailable";
      }

      const buckets = trimLeadingEmptyBuckets(normalizeAnalyticsItems(pick(data, ["recent_time_buckets", "recentTimeBuckets", "time_buckets", "timeBuckets", "buckets"]), "start"))
        .filter(bucketHasActivity);
      target.bucketCount.textContent = "";
      renderBucketChart(target, buckets);

      renderAnalyticsPairTable(
        target.queriedBody,
        target.queriedCount,
        normalizeAnalyticsItems(pick(data, ["top_queried_domains", "topQueriedDomains", "queried_domains", "queriedDomains"]), "domain"),
        "Domain",
        "No top queried domains reported.",
        "(hidden by privacy)",
        ["domain", "query_name", "queryName", "name"],
        true,
        totalQueryCount
      );
      renderAnalyticsPairTable(
        target.blockedBody,
        target.blockedCount,
        normalizeAnalyticsItems(pick(data, ["top_blocked_domains", "topBlockedDomains", "blocked_domains", "blockedDomains"]), "domain"),
        "Domain",
        "No top blocked domains reported.",
        "(hidden by privacy)",
        ["domain", "query_name", "queryName", "name"],
        true,
        totalQueryCount
      );
      renderAnalyticsPairTable(
        target.clientsBody,
        target.clientCount,
        normalizeAnalyticsItems(pick(data, ["top_clients", "topClients", "clients"]), "client_ip"),
        "Client",
        "No top clients reported.",
        "(hidden by privacy)",
        ["client_ip", "clientIP", "client", "name", "ip"],
        true,
        totalQueryCount
      );
      renderClientActivityChart(target, pick(data, ["client_time_buckets", "clientTimeBuckets", "client_buckets", "clientBuckets", "client_activity", "clientActivity"]));
    }

    async function refresh() {
      const [summary, settings] = await Promise.all([
        fetchOptionalJSON("/api/analytics/summary"),
        fetchOptionalJSON("/api/analytics/settings")
      ]);
      renderSummary(summary);
      renderSettings(settings);
      setUpdatedStatus("Analytics");
    }

    async function saveSettings(event) {
      event.preventDefault();
      if (!settingsAvailable) {
        setAnalyticsMessage("Analytics settings are unavailable.", true);
        return;
      }
      const payload = {
        privacy_level: Number(target.privacyLevel.value)
      };
      if (retentionAvailable) {
        const retention = retentionSeconds(target.retentionValue.value, target.retentionUnit.value);
        if (retention === undefined) {
          setAnalyticsMessage("Retention must be 0 or greater.", true);
          return;
        }
        payload.retention_duration_seconds = retention;
      }

      target.save.disabled = true;
      setAnalyticsMessage("Saving analytics settings...");
      try {
        const settings = await fetchJSON("/api/analytics/settings", {
          method: "PUT",
          headers: {"content-type": "application/json"},
          body: JSON.stringify(payload)
        });
        renderSettings({ok: true, data: settings});
        renderSummary(await fetchOptionalJSON("/api/analytics/summary"));
        setAnalyticsMessage("Analytics settings saved.", false);
      } catch (err) {
        setAnalyticsMessage("Analytics settings update failed: " + err.message, true);
      } finally {
        target.save.disabled = !settingsAvailable;
      }
    }

    async function cleanupAnalytics() {
      target.cleanup.disabled = true;
      setAnalyticsMessage("Running analytics cleanup...");
      try {
        const result = await fetchJSON("/api/analytics/cleanup", {method: "POST"});
        const deleted = pick(result || {}, ["deleted", "count", "removed"]);
        setAnalyticsMessage("Analytics cleanup removed " + displayNumber(deleted || 0) + " expired events.", false);
        renderSummary(await fetchOptionalJSON("/api/analytics/summary"));
      } catch (err) {
        setAnalyticsMessage("Analytics cleanup failed: " + err.message, true);
      } finally {
        target.cleanup.disabled = !settingsAvailable;
      }
    }

    on(target.privacyLevel, "change", () => {
      target.privacyNote.textContent = privacyDescription(target.privacyLevel.value);
    });
    on(target.form, "submit", saveSettings);
    on(target.cleanup, "click", cleanupAnalytics);

    return {refresh};
  }
});
