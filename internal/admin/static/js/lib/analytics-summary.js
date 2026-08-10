import {firstDefined, pick} from "./format.js";

export function normalizeAnalyticsItems(value, nameKey) {
  if (Array.isArray(value)) {
    return value;
  }
  if (value && typeof value === "object") {
    return Object.entries(value).map(([name, count]) => {
      const item = {};
      item[nameKey] = name;
      item.count = count;
      return item;
    });
  }
  return [];
}

export function countValue(value) {
  if (typeof value === "number" && Number.isFinite(value)) {
    return Math.max(0, value);
  }
  if (typeof value === "string" && value.trim() !== "" && !Number.isNaN(Number(value))) {
    return Math.max(0, Number(value));
  }
  return undefined;
}

export function analyticsCount(item) {
  const value = pick(item, ["count", "total", "queries", "blocked_count", "blockedCount", "request_count", "requestCount"]);
  return countValue(value) || 0;
}

export function analyticsTotalQueryCount(data) {
  const explicit = countValue(firstDefined(data || {}, [
    "total_query_count",
    "totalQueryCount",
    "total_queries",
    "totalQueries",
    "query_count",
    "queryCount"
  ]));
  if (explicit !== undefined) {
    return explicit;
  }
  const totals = normalizeAnalyticsItems(pick(data || {}, [
    "totals_by_action", "totalsByAction", "totals", "actions"
  ]), "action");
  return totals.length ? totals.reduce((sum, row) => sum + analyticsCount(row), 0) : undefined;
}

export function analyticsActionCount(summaryResult, actionNames) {
  if (!summaryResult || !summaryResult.ok) {
    return undefined;
  }
  const totals = normalizeAnalyticsItems(pick(summaryResult.data || {}, [
    "totals_by_action", "totalsByAction", "totals", "actions"
  ]), "action");
  const names = new Set(actionNames.map(name => String(name).toLowerCase()));
  for (const row of totals) {
    const action = String(pick(row, ["action", "name", "status", "result"]) || "").toLowerCase();
    if (names.has(action)) {
      return analyticsCount(row);
    }
  }
  return undefined;
}

export function analyticsTotalCount(summaryResult) {
  if (!summaryResult || !summaryResult.ok) {
    return undefined;
  }
  return analyticsTotalQueryCount(summaryResult.data || {});
}
