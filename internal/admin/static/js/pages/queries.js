import {initAdminPage} from "../admin.js";
import {fetchJSON, fetchOptionalJSON} from "../lib/api.js";
import {on, qsa, required} from "../lib/dom.js";
import {classifyAction, cloneTemplate, configureTemplates, emptyRow, setPillElement, setTemplateText, templateField} from "../lib/elements.js";
import {displayNumber, displayValue, dnsQtypeNames, firstDefined, formatTime, listFrom, pick} from "../lib/format.js";

const queryLogRefreshIntervalMS = 5000;
const queryPageLimit = 100;
const queryColumnStorageKey = "corehole.queryLog.visibleColumns";
const queryColumns = [
  {key: "time", label: "Time", defaultVisible: true},
  {key: "client", label: "Client IP", defaultVisible: true},
  {key: "domain", label: "Domain", defaultVisible: true},
  {key: "type", label: "Type", defaultVisible: true},
  {key: "action", label: "Action", defaultVisible: true},
  {key: "response", label: "Response", defaultVisible: true},
  {key: "duration", label: "Duration ms", defaultVisible: true},
  {key: "upstream", label: "Upstream", defaultVisible: false},
  {key: "cache", label: "Cache", defaultVisible: false},
  {key: "forward_duration", label: "Forward ms", defaultVisible: false},
  {key: "retries", label: "Retries", defaultVisible: false},
  {key: "forward_error", label: "Upstream error", defaultVisible: false},
  {key: "reason", label: "Reason", defaultVisible: true},
  {key: "actions", label: "Actions", defaultVisible: true}
];

function pageFields() {
  return {
    form: required("#query-filter-form"),
    from: required("#query-filter-from"),
    to: required("#query-filter-to"),
    client: required("#query-filter-client"),
    domain: required("#query-filter-domain"),
    type: required("#query-filter-type"),
    action: required("#query-filter-action"),
    response: required("#query-filter-response"),
    ruleID: required("#query-filter-rule-id"),
    blocklistID: required("#query-filter-blocklist-id"),
    durationMin: required("#query-filter-duration-min"),
    durationMax: required("#query-filter-duration-max"),
    prev: required("#query-page-prev"),
    reload: required("#query-page-reload"),
    next: required("#query-page-next"),
    status: required("#query-page-status"),
    columnToggle: required("#query-column-toggle"),
    columnPanel: required("#query-column-panel"),
    sortButtons: qsa("[data-query-sort]"),
    count: required("#query-count"),
    body: required("#query-body")
  };
}

function normalizeQueries(data) {
  if (Array.isArray(data)) {
    return data;
  }
  return listFrom(pick(data, ["queries", "items", "results", "entries", "data"]));
}

function displayQueryType(value) {
  if (value === undefined || value === null || value === "") {
    return value;
  }
  const text = String(value).trim();
  const numeric = Number(text);
  if (Number.isInteger(numeric) && numeric >= 0) {
    return dnsQtypeNames[numeric] || "TYPE" + numeric;
  }
  return text.toUpperCase();
}

function parseQueryTime(value) {
  if (!value) {
    return NaN;
  }
  const time = new Date(value).getTime();
  return Number.isNaN(time) ? NaN : time;
}

function queryFilterText(value) {
  if (value === undefined || value === null) {
    return "";
  }
  return String(value).toLowerCase();
}

function queryDurationNumber(value) {
  if (value === undefined || value === null || value === "") {
    return NaN;
  }
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : NaN;
}

function blockableDomain(value) {
  const domain = String(value || "").trim().replace(/\.+$/, "").toLowerCase();
  if (!domain || domain === "(hidden by privacy)" || domain === "hidden") {
    return "";
  }
  return domain;
}

function normalizeQueryEntry(query) {
  const time = pick(query, ["time", "timestamp", "created_at", "createdAt", "when"]);
  const client = pick(query, ["client_ip", "clientIP", "client", "remote_addr", "remoteAddr", "source"]);
  const queryName = firstDefined(query, ["query_name", "queryName"]);
  const domain = queryName === "" ? "" : pick(query, ["query_name", "queryName", "domain", "qname", "name", "question"]);
  const rawType = pick(query, ["type", "qtype", "query_type", "queryType"]);
  const action = pick(query, ["action", "status", "decision", "result"]);
  const response = pick(query, ["response", "answer", "rcode", "reply"]);
  const reason = pick(query, ["reason", "rule", "matched_rule", "matchedRule", "source_list", "sourceList"]);
  const ruleID = firstDefined(query, ["rule_id", "ruleID", "rule.id"]);
  const blocklistID = firstDefined(query, ["blocklist_id", "blocklistID", "blocklist.id", "list_id", "listID"]);
  const durationMS = firstDefined(query, ["duration_ms", "durationMS", "duration", "latency_ms", "latencyMS"]);
  const upstream = firstDefined(query, ["upstream_resolver", "upstreamResolver", "upstream"]);
  const cacheStatus = firstDefined(query, ["cache_status", "cacheStatus", "cache"]);
  const forwardDurationMS = firstDefined(query, ["forward_duration_ms", "forwardDurationMS", "forward_duration", "forwardDuration"]);
  const retryCount = firstDefined(query, ["retry_count", "retryCount", "retries"]);
  const forwardError = firstDefined(query, ["forward_error", "forwardError", "upstream_error", "upstreamError"]);
  return {
    time,
    timeMS: parseQueryTime(time),
    client,
    domain,
    rawType,
    type: displayQueryType(rawType),
    action,
    response,
    reason,
    ruleID,
    blocklistID,
    durationMS,
    durationValue: queryDurationNumber(durationMS),
    upstream,
    cacheStatus,
    forwardDurationMS,
    retryCount,
    forwardError
  };
}

function appendQueryParam(params, name, value) {
  if (value !== undefined && value !== null && String(value).trim() !== "") {
    params.set(name, String(value).trim());
  }
}

function appendDateTimeParam(params, name, value) {
  const trimmed = String(value || "").trim();
  if (!trimmed) {
    return;
  }
  const parsed = new Date(trimmed);
  params.set(name, Number.isNaN(parsed.getTime()) ? trimmed : parsed.toISOString());
}

function syncQueryFilterOptions(select, values) {
  const existing = new Set(Array.from(select.options).map(option => option.value.toLowerCase()));
  for (const value of values) {
    const text = String(value || "").trim();
    if (!text || existing.has(text.toLowerCase())) {
      continue;
    }
    const option = document.createElement("option");
    option.value = text;
    option.textContent = text;
    select.appendChild(option);
    existing.add(text.toLowerCase());
  }
}

function queryPaginationValue(value) {
  const numeric = Number(value);
  return Number.isInteger(numeric) && numeric >= 0 ? numeric : null;
}

function defaultVisibleColumns() {
  return new Set(queryColumns.filter(column => column.defaultVisible).map(column => column.key));
}

function loadVisibleColumns() {
  try {
    const raw = window.localStorage.getItem(queryColumnStorageKey);
    const parsed = JSON.parse(raw || "[]");
    if (Array.isArray(parsed) && parsed.length) {
      const known = new Set(queryColumns.map(column => column.key));
      const visible = new Set(parsed.filter(key => known.has(key)));
      if (visible.size) {
        return visible;
      }
    }
  } catch (_) {
    // Ignore invalid local view state.
  }
  return defaultVisibleColumns();
}

function saveVisibleColumns(visibleColumns) {
  try {
    window.localStorage.setItem(queryColumnStorageKey, JSON.stringify(Array.from(visibleColumns)));
  } catch (_) {
    // Local storage can be unavailable in private or restricted browser contexts.
  }
}

function displayRetryCount(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 0) {
    return "";
  }
  return String(numeric);
}

initAdminPage({
  label: "Query log",
  init({isAuthenticated, setUpdated, setUpdatedStatus}) {
    const fields = pageFields();
    let currentQueries = [];
    let currentSort = {field: "timestamp", order: "desc"};
    let currentPage = {limit: queryPageLimit, offset: 0, nextOffset: null, previousOffset: null, hasNext: false, hasPrevious: false};
    let refreshTimer = 0;
    let refreshInFlight = false;
    let filterRefreshTimer = 0;
    let visibleColumns = loadVisibleColumns();

    configureTemplates({
      emptyRow: required("#template-empty-row"),
      queryRow: required("#template-query-row")
    });

    function activeFilters() {
      return {
        from: fields.from.value.trim(),
        to: fields.to.value.trim(),
        client: fields.client.value.trim(),
        domain: fields.domain.value.trim(),
        type: fields.type.value.trim(),
        action: fields.action.value.trim(),
        response: fields.response.value.trim(),
        ruleID: fields.ruleID.value.trim(),
        blocklistID: fields.blocklistID.value.trim(),
        durationMinRaw: fields.durationMin.value.trim(),
        durationMaxRaw: fields.durationMax.value.trim()
      };
    }

    function hasActiveFilters() {
      const filters = activeFilters();
      return Boolean(
        filters.from ||
        filters.to ||
        filters.client ||
        filters.domain ||
        filters.type ||
        filters.action ||
        filters.response ||
        filters.ruleID ||
        filters.blocklistID ||
        filters.durationMinRaw ||
        filters.durationMaxRaw
      );
    }

    function visibleColumnCount() {
      return queryColumns.reduce((count, column) => count + (visibleColumns.has(column.key) ? 1 : 0), 0);
    }

    function applyColumnVisibility(root) {
      const scope = root || document;
      for (const column of queryColumns) {
        const hidden = !visibleColumns.has(column.key);
        for (const element of scope.querySelectorAll('[data-column="' + column.key + '"]')) {
          element.hidden = hidden;
        }
      }
    }

    function syncColumnPanel() {
      fields.columnPanel.textContent = "";
      for (const column of queryColumns) {
        const id = "query-column-" + column.key;
        const label = document.createElement("label");
        label.className = "column-menu-option";
        label.setAttribute("for", id);
        label.setAttribute("role", "menuitemcheckbox");
        label.setAttribute("aria-checked", visibleColumns.has(column.key) ? "true" : "false");

        const input = document.createElement("input");
        input.id = id;
        input.type = "checkbox";
        input.checked = visibleColumns.has(column.key);
        input.dataset.column = column.key;

        const text = document.createElement("span");
        text.textContent = column.label;

        label.append(input, text);
        fields.columnPanel.appendChild(label);
      }
    }

    function setColumnPanelOpen(open) {
      fields.columnPanel.classList.toggle("hidden", !open);
      fields.columnToggle.setAttribute("aria-expanded", open ? "true" : "false");
    }

    function updateColumnVisibility() {
      if (visibleColumns.size === 0) {
        visibleColumns = defaultVisibleColumns();
      }
      saveVisibleColumns(visibleColumns);
      syncColumnPanel();
      applyColumnVisibility(document);
    }

    function buildURL(offset) {
      const filters = activeFilters();
      const params = new URLSearchParams();
      params.set("limit", String(queryPageLimit));
      params.set("offset", String(Math.max(0, Number(offset) || 0)));
      params.set("sort", currentSort.field);
      params.set("order", currentSort.order);
      appendDateTimeParam(params, "from", filters.from);
      appendDateTimeParam(params, "to", filters.to);
      appendQueryParam(params, "client_ip", filters.client);
      appendQueryParam(params, "domain", filters.domain);
      appendQueryParam(params, "type", filters.type);
      appendQueryParam(params, "action", filters.action);
      appendQueryParam(params, "response", filters.response);
      appendQueryParam(params, "rule_id", filters.ruleID);
      appendQueryParam(params, "blocklist_id", filters.blocklistID);
      appendQueryParam(params, "duration_min", filters.durationMinRaw);
      appendQueryParam(params, "duration_max", filters.durationMaxRaw);
      return "/api/queries?" + params.toString();
    }

    function syncFilterOptions(queries) {
      syncQueryFilterOptions(fields.type, queries.map(query => query.type));
      syncQueryFilterOptions(fields.action, queries.map(query => query.action));
      syncQueryFilterOptions(fields.response, queries.map(query => query.response));
    }

    function normalizePage(data) {
      const queries = normalizeQueries(data);
      const limit = queryPaginationValue(pick(data, ["limit"])) || queryPageLimit;
      const offset = queryPaginationValue(pick(data, ["offset"])) || 0;
      return {
        queries,
        limit,
        offset,
        nextOffset: queryPaginationValue(pick(data, ["next_offset", "nextOffset"])),
        previousOffset: queryPaginationValue(pick(data, ["previous_offset", "previousOffset"])),
        hasNext: pick(data, ["has_next", "hasNext"]) === true,
        hasPrevious: pick(data, ["has_previous", "hasPrevious"]) === true,
        sort: pick(data, ["sort"]) || currentSort.field,
        order: pick(data, ["order"]) || currentSort.order
      };
    }

    function updatePaginationControls() {
      fields.prev.disabled = !currentPage.hasPrevious || currentPage.previousOffset === null;
      fields.next.disabled = !currentPage.hasNext || currentPage.nextOffset === null;
      const page = Math.floor(currentPage.offset / Math.max(1, currentPage.limit)) + 1;
      fields.status.textContent = "Page " + displayNumber(page);
    }

    function renderSortState() {
      for (const button of fields.sortButtons) {
        const active = button.dataset.querySort === currentSort.field;
        button.setAttribute("aria-pressed", active ? "true" : "false");
        button.setAttribute("aria-label", button.textContent.replace(/[↕↑↓]/g, "").trim() + ", " + (active ? currentSort.order + "ending" : "not sorted"));
        const indicator = button.querySelector(".query-sort-indicator");
        if (indicator) {
          indicator.textContent = active ? (currentSort.order === "asc" ? "↑" : "↓") : "↕";
          indicator.classList.toggle("active", active);
        }
      }
    }

    function renderRows() {
      const queries = currentQueries.map(normalizeQueryEntry);
      syncFilterOptions(queries);
      fields.body.textContent = "";
      if (queries.length) {
        const start = currentPage.offset + 1;
        const end = currentPage.offset + queries.length;
        fields.count.textContent = displayNumber(start) + "-" + displayNumber(end) + " shown";
      } else {
        fields.count.textContent = "0 shown";
      }
      if (!queries.length) {
        fields.body.appendChild(emptyRow(visibleColumnCount(), hasActiveFilters() ? "No queries match filters." : "No queries reported."));
        applyColumnVisibility(fields.body);
        updatePaginationControls();
        renderSortState();
        return;
      }
      for (const query of queries) {
        const tr = cloneTemplate("queryRow");
        setTemplateText(tr, "time", formatTime(query.time));
        setTemplateText(tr, "client", query.client);
        setTemplateText(tr, "domain", query.domain);
        setTemplateText(tr, "type", query.type);
        setPillElement(templateField(tr, "action"), query.action, classifyAction(query.action));
        setTemplateText(tr, "response", query.response);
        setTemplateText(tr, "duration-ms", query.durationMS);
        setTemplateText(tr, "upstream", query.upstream);
        setTemplateText(tr, "cache-status", query.cacheStatus);
        setTemplateText(tr, "forward-duration-ms", query.forwardDurationMS);
        setTemplateText(tr, "retries", displayRetryCount(query.retryCount));
        setTemplateText(tr, "forward-error", query.forwardError);
        setTemplateText(tr, "reason", query.reason);
        const blockButton = tr.querySelector("button[data-action='block-domain']");
        const domain = blockableDomain(query.domain);
        if (blockButton) {
          blockButton.dataset.domain = domain;
          blockButton.disabled = !domain || String(query.action).toLowerCase() === "block";
          blockButton.textContent = String(query.action).toLowerCase() === "block" ? "Blocked" : "Block";
          blockButton.title = domain ? "Create an exact deny rule for " + domain : "Domain is unavailable.";
        }
        applyColumnVisibility(tr);
        fields.body.appendChild(tr);
      }
      updatePaginationControls();
      renderSortState();
    }

    function renderQueries(data) {
      const page = normalizePage(data || {});
      currentQueries = page.queries;
      currentPage = {
        limit: page.limit,
        offset: page.offset,
        nextOffset: page.nextOffset,
        previousOffset: page.previousOffset,
        hasNext: page.hasNext,
        hasPrevious: page.hasPrevious
      };
      currentSort = {field: String(page.sort), order: String(page.order)};
      renderRows();
    }

    function renderUnavailable(error) {
      currentQueries = [];
      currentPage = {limit: queryPageLimit, offset: 0, nextOffset: null, previousOffset: null, hasNext: false, hasPrevious: false};
      fields.body.textContent = "";
      fields.count.textContent = "Unavailable: " + displayValue(error);
      fields.body.appendChild(emptyRow(visibleColumnCount(), "Query log unavailable."));
      applyColumnVisibility(fields.body);
      updatePaginationControls();
      renderSortState();
    }

    async function blockDomain(button) {
      const domain = blockableDomain(button.dataset.domain);
      if (!domain) {
        setUpdated("Cannot block this query because the domain is unavailable.");
        return;
      }
      button.disabled = true;
      try {
        await fetchJSON("/api/filter/rules", {
          method: "POST",
          headers: {"content-type": "application/json"},
          body: JSON.stringify({
            pattern: domain,
            kind: "deny",
            match_type: "exact",
            enabled: true,
            comment: "Created from query log"
          })
        });
        setUpdated("Added deny rule for " + domain + ".");
        await loadPage(currentPage.offset);
      } catch (err) {
        button.disabled = false;
        setUpdated("Block rule create failed: " + err.message);
      }
    }

    async function loadPage(offset) {
      const result = await fetchOptionalJSON(buildURL(offset));
      if (!result.ok) {
        renderUnavailable(result.error);
        setUpdatedStatus("Query log");
        return;
      }
      renderQueries(result.data || {});
      setUpdatedStatus("Query log");
    }

    function schedulePageReload() {
      if (filterRefreshTimer) {
        window.clearTimeout(filterRefreshTimer);
      }
      filterRefreshTimer = window.setTimeout(() => {
        filterRefreshTimer = 0;
        loadPage(0).catch(err => setUpdated("Query log refresh failed: " + err.message));
      }, 250);
    }

    function canAutoRefresh() {
      return currentPage.offset === 0 &&
        currentSort.field === "timestamp" &&
        currentSort.order === "desc" &&
        !hasActiveFilters();
    }

    async function liveRefresh() {
      if (!isAuthenticated() || document.visibilityState === "hidden" || refreshInFlight || !canAutoRefresh()) {
        return;
      }
      refreshInFlight = true;
      try {
        renderQueries(await fetchJSON(buildURL(0)) || {});
        setUpdatedStatus("Live data");
      } catch (err) {
        if (err.message !== "authentication_required") {
          setUpdated("Live refresh failed: " + err.message);
        }
      } finally {
        refreshInFlight = false;
      }
    }

    on(fields.form, "submit", event => {
      event.preventDefault();
      if (filterRefreshTimer) {
        window.clearTimeout(filterRefreshTimer);
        filterRefreshTimer = 0;
      }
      loadPage(0).catch(err => setUpdated("Query log refresh failed: " + err.message));
    });
    on(fields.form, "input", schedulePageReload);
    on(fields.form, "change", schedulePageReload);
    on(fields.form, "reset", () => {
      window.setTimeout(() => {
        loadPage(0).catch(err => setUpdated("Query log refresh failed: " + err.message));
      }, 0);
    });
    on(fields.body, "click", event => {
      const button = event.target.closest("button[data-action='block-domain']");
      if (button) {
        blockDomain(button);
      }
    });
    on(fields.columnToggle, "click", () => {
      setColumnPanelOpen(fields.columnPanel.classList.contains("hidden"));
    });
    on(fields.columnPanel, "change", event => {
      const input = event.target.closest("input[data-column]");
      if (!input) {
        return;
      }
      if (input.checked) {
        visibleColumns.add(input.dataset.column);
      } else {
        visibleColumns.delete(input.dataset.column);
      }
      updateColumnVisibility();
    });
    on(document, "click", event => {
      if (!event.target.closest(".query-column-menu")) {
        setColumnPanelOpen(false);
      }
    });
    fields.sortButtons.forEach(button => {
      button.addEventListener("click", () => {
        const field = button.dataset.querySort;
        const order = currentSort.field === field && currentSort.order === "asc" ? "desc" : "asc";
        currentSort = {field, order};
        renderSortState();
        loadPage(0).catch(err => setUpdated("Query log refresh failed: " + err.message));
      });
    });
    on(fields.prev, "click", () => {
      if (currentPage.previousOffset !== null) {
        loadPage(currentPage.previousOffset).catch(err => setUpdated("Query log refresh failed: " + err.message));
      }
    });
    on(fields.reload, "click", () => {
      loadPage(currentPage.offset).catch(err => setUpdated("Query log refresh failed: " + err.message));
    });
    on(fields.next, "click", () => {
      if (currentPage.nextOffset !== null) {
        loadPage(currentPage.nextOffset).catch(err => setUpdated("Query log refresh failed: " + err.message));
      }
    });
    updateColumnVisibility();

    return {
      refresh: () => loadPage(currentPage.offset),
      start() {
        if (!refreshTimer && isAuthenticated() && document.visibilityState !== "hidden") {
          refreshTimer = window.setInterval(liveRefresh, queryLogRefreshIntervalMS);
        }
      },
      stop() {
        if (refreshTimer) {
          window.clearInterval(refreshTimer);
          refreshTimer = 0;
        }
      }
    };
  }
});
