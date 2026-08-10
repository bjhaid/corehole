import {initAdminPage} from "../admin.js";
import {fetchJSON, fetchOptionalJSON} from "../lib/api.js";
import {required} from "../lib/dom.js";
import {configureTemplates, setText} from "../lib/elements.js";
import {analyticsActionCount, analyticsTotalCount} from "../lib/analytics-summary.js";
import {bundledConfigValue, displayNumber, firstDefined, listFrom, pick} from "../lib/format.js";
import {renderUpstreamRows} from "../lib/upstreams.js";

const refreshIntervalMS = 5000;

function fields() {
  return {
    recent: required("#card-recent"),
    blocked: required("#card-blocked"),
    allowed: required("#card-allowed"),
    dropped: required("#card-dropped"),
    dashboardDNSListen: required("#dashboard-dns-listen"),
    dashboardAdminListen: required("#dashboard-admin-listen"),
    blockingResponse: required("#blocking-response"),
    bundledState: required("#bundled-state"),
    blocklistCount: required("#blocklist-count"),
    dashboardBlocklistStatus: required("#dashboard-blocklist-status"),
    dashboardUpstreamCount: required("#dashboard-upstream-count"),
    dashboardUpstreamBody: required("#dashboard-upstream-body")
  };
}

function dashboardCount(data, paths, fallback) {
  const value = firstDefined(data, paths);
  return value === undefined ? fallback : value;
}

function normalizeFilterLists(data) {
  if (Array.isArray(data)) {
    return data;
  }
  return listFrom(pick(data, ["lists", "items", "results", "data"]));
}

function renderBundledState(target, data) {
  const bundled = bundledConfigValue(data);
  target.bundledState.textContent = typeof bundled === "boolean" ? (bundled ? "enabled" : "disabled") : "unavailable";
}

function renderDashboard(target, data, config, filterResult, analyticsSummary) {
  const dashboard = data || {};
  const details = Object.assign({}, config || {}, dashboard);
  target.recent.textContent = displayNumber(dashboardCount(dashboard, [
    "total_queries", "totalQueries", "total_query_count", "totalQueryCount", "query_count", "queryCount", "queries", "total_recent_queries", "totalRecentQueries", "recent_queries", "recentQueries"
  ], analyticsTotalCount(analyticsSummary)));
  target.blocked.textContent = displayNumber(dashboardCount(dashboard, [
    "blocked_queries", "blockedQueries", "total_blocked_queries", "totalBlockedQueries", "blocked_count", "blockedCount", "blocked", "blocked_recent_queries", "blockedRecentQueries"
  ], analyticsActionCount(analyticsSummary, ["block", "blocked", "deny", "denied"])));
  target.allowed.textContent = displayNumber(dashboardCount(dashboard, [
    "allowed_queries", "allowedQueries", "total_allowed_queries", "totalAllowedQueries", "allowed_count", "allowedCount", "allowed", "allowed_recent_queries", "allowedRecentQueries"
  ], analyticsActionCount(analyticsSummary, ["allow", "allowed"])));
  target.dropped.textContent = displayNumber(firstDefined(dashboard, [
    "dropped_audit_events", "droppedAuditEvents", "audit_dropped", "auditDropped", "dropped_events", "droppedEvents"
  ]));
  setText(target.dashboardDNSListen, pick(details, [
    "dns_listen", "dnsListen", "dns_address", "dnsAddress", "listen_dns", "listenDNS", "dns.listen", "server.dns_listen", "server.dnsListen"
  ]));
  setText(target.dashboardAdminListen, pick(details, [
    "admin_listen", "adminListen", "admin_address", "adminAddress", "listen_admin", "listenAdmin", "admin.listen", "server.admin_listen", "server.adminListen"
  ]));
  setText(target.blockingResponse, pick(details, [
    "blocking_response", "blockingResponse", "block_response", "blockResponse", "blocking.response", "dns.blocking_response"
  ]));
  renderBundledState(target, details);

  const configuredBlocklists = listFrom(pick(details, [
    "blocklists", "blocklist_paths", "blocklistPaths", "blocking.blocklists"
  ]));
  const reportedBlocklistCount = firstDefined(details, [
    "blocklist_count", "blocklistCount", "blocklists_count", "blocklistsCount", "blocking.blocklist_count"
  ]);
  const blocklistCount = reportedBlocklistCount === undefined ? configuredBlocklists.length : reportedBlocklistCount;
  target.blocklistCount.textContent = displayNumber(blocklistCount);
  if (filterResult && filterResult.ok) {
    const subscribed = normalizeFilterLists(filterResult.data).length;
    target.dashboardBlocklistStatus.textContent = subscribed + " subscribed, " + configuredBlocklists.length + " configured";
  } else if (filterResult && !filterResult.ok) {
    target.dashboardBlocklistStatus.textContent = displayNumber(blocklistCount) + " configured; subscribed lists unavailable";
  } else {
    target.dashboardBlocklistStatus.textContent = displayNumber(blocklistCount) + " configured";
  }

  renderUpstreamRows(listFrom(pick(details, [
    "upstreams", "upstream_resolvers", "upstreamResolvers", "resolvers", "dns_upstreams", "dnsUpstreams", "dns.upstreams"
  ])), target.dashboardUpstreamCount, target.dashboardUpstreamBody, false);
}

initAdminPage({
  label: "Dashboard",
  init({isAuthenticated, setUpdated, setUpdatedStatus}) {
    const target = fields();
    let config = {};
    let filterResult = null;
    let analyticsSummary = null;
    let timer = 0;
    let liveInFlight = false;

    configureTemplates({
      emptyRow: required("#template-empty-row"),
      upstreamDashboardRow: required("#template-upstream-dashboard-row")
    });

    function shouldRefresh() {
      return isAuthenticated() && document.visibilityState !== "hidden";
    }

    async function refresh() {
      const [dashboard, nextConfig, filterLists, summary] = await Promise.all([
        fetchJSON("/api/dashboard"),
        fetchOptionalJSON("/api/config"),
        fetchOptionalJSON("/api/filter/lists"),
        fetchOptionalJSON("/api/analytics/summary")
      ]);
      if (nextConfig.ok) {
        config = nextConfig.data || {};
      }
      filterResult = filterLists;
      analyticsSummary = summary;
      renderDashboard(target, dashboard || {}, nextConfig.ok ? nextConfig.data || {} : config, filterResult, analyticsSummary);
      setUpdatedStatus("Dashboard");
    }

    async function refreshLive() {
      if (!shouldRefresh() || liveInFlight) {
        return;
      }
      liveInFlight = true;
      try {
        const [dashboard, summary] = await Promise.all([
          fetchJSON("/api/dashboard"),
          fetchOptionalJSON("/api/analytics/summary")
        ]);
        analyticsSummary = summary;
        renderDashboard(target, dashboard || {}, config, filterResult, analyticsSummary);
        setUpdatedStatus("Live data");
      } catch (err) {
        if (err.message !== "authentication_required") {
          setUpdated("Live refresh failed: " + err.message);
        }
      } finally {
        liveInFlight = false;
      }
    }

    return {
      refresh,
      start() {
        if (!timer && shouldRefresh()) {
          timer = window.setInterval(refreshLive, refreshIntervalMS);
        }
      },
      stop() {
        if (timer) {
          window.clearInterval(timer);
          timer = 0;
        }
      }
    };
  }
});
