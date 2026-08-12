import {initAdminPage} from "../admin.js";
import {fetchJSON, fetchOptionalJSON} from "../lib/api.js";
import {on, required} from "../lib/dom.js";
import {actionButton, cell, configureTemplates, emptyRow, pill, setText} from "../lib/elements.js";
import {boolLabel, displayValue, dnssecConfigValue, formatTime, listFrom, pick} from "../lib/format.js";
import {setFormDisabled} from "../lib/forms.js";
import {renderUpstreamRows} from "../lib/upstreams.js";

function fields() {
  return {
    dnsListen: required("#dns-listen"),
    adminListen: required("#admin-listen"),
    dnssecState: required("#dnssec-state"),
    dnssecForm: required("#dnssec-form"),
    dnssecMode: required("#dnssec-mode"),
    dnssecMessage: required("#dnssec-message"),
    dnssecNote: required("#dnssec-note"),
    cacheState: required("#cache-state"),
    cacheForm: required("#cache-form"),
    cacheSuccessTTL: required("#cache-success-ttl"),
    cacheDenialTTL: required("#cache-denial-ttl"),
    cacheSuccessCapacity: required("#cache-success-capacity"),
    cacheDenialCapacity: required("#cache-denial-capacity"),
    cachePrefetchAmount: required("#cache-prefetch-amount"),
    cachePrefetchDuration: required("#cache-prefetch-duration"),
    cachePrefetchPercent: required("#cache-prefetch-percent"),
    cacheMessage: required("#cache-message"),
    blockingResponseState: required("#blocking-response-state"),
    blockingResponseForm: required("#blocking-response-form"),
    blockingResponseMode: required("#blocking-response-mode"),
    blockingResponseMessage: required("#blocking-response-message"),
    loggingState: required("#logging-state"),
    loggingForm: required("#logging-form"),
    loggingLevel: required("#logging-level"),
    loggingFormat: required("#logging-format"),
    loggingMessage: required("#logging-message"),
    upstreamCount: required("#upstream-count"),
    upstreamForm: required("#upstream-form"),
    upstreamIndex: required("#upstream-index"),
    upstreamName: required("#upstream-name"),
    upstreamAddress: required("#upstream-address"),
    upstreamProtocol: required("#upstream-protocol"),
    upstreamTLSServerName: required("#upstream-tls-server-name"),
    upstreamEnabled: required("#upstream-enabled"),
    upstreamSave: required("#upstream-save"),
    upstreamCancel: required("#upstream-cancel"),
    upstreamMessage: required("#upstream-message"),
    upstreamBody: required("#upstream-body"),
    apiKeyStatus: required("#api-key-status"),
    apiKeyForm: required("#api-key-form"),
    apiKeyName: required("#api-key-name"),
    apiKeyCreate: required("#api-key-create"),
    apiKeySecret: required("#api-key-secret"),
    apiKeyBody: required("#api-key-body")
  };
}

function normalizeAPIKeys(data) {
  if (Array.isArray(data)) {
    return data;
  }
  return listFrom(pick(data, ["api_keys", "apiKeys", "keys", "items", "results", "data"]));
}

function normalizeDNSSECConfig(data) {
  const raw = dnssecConfigValue(data);
  if (!raw || typeof raw !== "object") {
    return {enabled: false, mode: "off"};
  }
  const enabled = Boolean(pick(raw, ["enabled"]));
  let mode = String(pick(raw, ["mode"]) || "").toLowerCase();
  if (enabled && mode === "") {
    mode = "upstream";
  }
  if (mode !== "upstream" || !enabled) {
    return {enabled: false, mode: "off"};
  }
  return {enabled: true, mode: "upstream"};
}

initAdminPage({
  label: "Settings / API Keys",
  init({setUpdated, setUpdatedStatus}) {
    const target = fields();
    let currentUpstreams = [];
    let currentAPIKeys = [];
    let configUpdateAvailable = true;
    let apiKeysAvailable = false;

    configureTemplates({
      emptyRow: required("#template-empty-row"),
      upstreamSettingsRow: required("#template-upstream-settings-row")
    });

    function setUpstreamMessage(text, isError) {
      target.upstreamMessage.textContent = text || "";
      target.upstreamMessage.classList.toggle("error", Boolean(isError));
    }

    function setDNSSECMessage(text, isError) {
      target.dnssecMessage.textContent = text || "";
      target.dnssecMessage.classList.toggle("error", Boolean(isError));
    }

    function setCacheMessage(text, isError) {
      target.cacheMessage.textContent = text || "";
      target.cacheMessage.classList.toggle("error", Boolean(isError));
    }

    function setLoggingMessage(text, isError) {
      target.loggingMessage.textContent = text || "";
      target.loggingMessage.classList.toggle("error", Boolean(isError));
    }

    function setBlockingResponseMessage(text, isError) {
      target.blockingResponseMessage.textContent = text || "";
      target.blockingResponseMessage.classList.toggle("error", Boolean(isError));
    }

    function setAPIKeyMessage(text, isError) {
      target.apiKeySecret.textContent = text || "";
      target.apiKeySecret.classList.toggle("error", Boolean(isError));
    }

    function syncLoggingControls() {
      setFormDisabled(target.loggingForm, !configUpdateAvailable);
    }

    function resetUpstreamForm() {
      target.upstreamIndex.value = "";
      target.upstreamForm.reset();
      target.upstreamProtocol.value = "udp";
      target.upstreamEnabled.checked = true;
      target.upstreamSave.textContent = "Add resolver";
      target.upstreamCancel.classList.add("hidden");
    }

    function renderDNSSEC(data) {
      const dnssec = normalizeDNSSECConfig(data);
      target.dnssecMode.value = dnssec.mode;
      target.dnssecState.textContent = dnssec.mode === "upstream"
        ? "upstream trusted validation"
        : "disabled";
      target.dnssecNote.textContent = dnssec.mode === "upstream"
        ? "Requests include DNSSEC flags for upstream validation; local recursive validation is unavailable."
        : "DNSSEC assistance is off; local recursive validation is unavailable.";
      setFormDisabled(target.dnssecForm, !configUpdateAvailable);
    }

    function renderCache(data) {
      const numberValue = (value, fallback) => Number(value === undefined ? fallback : value);
      const legacyTTL = numberValue(pick(data, ["cache_ttl", "cacheTTL", "dns.cache_ttl"]), 0);
      const successTTL = numberValue(pick(data, ["cache_success_ttl", "cacheSuccessTTL", "dns.cache_success_ttl"]), legacyTTL);
      const denialTTL = numberValue(pick(data, ["cache_denial_ttl", "cacheDenialTTL", "dns.cache_denial_ttl"]), legacyTTL);
      const successCapacity = numberValue(pick(data, ["cache_success_capacity", "cacheSuccessCapacity", "dns.cache_success_capacity"]), 32768);
      const denialCapacity = numberValue(pick(data, ["cache_denial_capacity", "cacheDenialCapacity", "dns.cache_denial_capacity"]), 4096);
      const prefetchAmount = numberValue(pick(data, ["cache_prefetch_amount", "cachePrefetchAmount", "dns.cache_prefetch_amount"]), 0);
      const prefetchDuration = numberValue(pick(data, ["cache_prefetch_duration", "cachePrefetchDuration", "dns.cache_prefetch_duration"]), 60);
      const prefetchPercent = numberValue(pick(data, ["cache_prefetch_percent", "cachePrefetchPercent", "dns.cache_prefetch_percent"]), 10);
      target.cacheSuccessTTL.value = String(successTTL);
      target.cacheDenialTTL.value = String(denialTTL);
      target.cacheSuccessCapacity.value = String(successCapacity);
      target.cacheDenialCapacity.value = String(denialCapacity);
      target.cachePrefetchAmount.value = String(prefetchAmount);
      target.cachePrefetchDuration.value = String(prefetchDuration);
      target.cachePrefetchPercent.value = String(prefetchPercent);
      target.cacheState.textContent = successTTL > 0 || denialTTL > 0
        ? successTTL + "s success / " + denialTTL + "s failure"
        : "disabled";
      setFormDisabled(target.cacheForm, !configUpdateAvailable);
    }

    function renderBlockingResponse(data) {
      const response = String(pick(data, ["blocking_response", "blockingResponse", "blocking.response"]) || "null-ip").toLowerCase();
      target.blockingResponseMode.value = ["null-ip", "nxdomain", "refused"].includes(response) ? response : "null-ip";
      target.blockingResponseState.textContent = target.blockingResponseMode.value === "null-ip"
        ? "0.0.0.0 / ::"
        : target.blockingResponseMode.value.toUpperCase();
      setFormDisabled(target.blockingResponseForm, !configUpdateAvailable);
    }

    function renderLogging(data) {
      const logging = pick(data, ["logging"]) || {};
      const level = String(pick(logging, ["level"]) || "info").toLowerCase();
      const format = String(pick(logging, ["format"]) || "text").toLowerCase();
      target.loggingLevel.value = ["debug", "info", "warn", "error"].includes(level) ? level : "info";
      target.loggingFormat.value = ["text", "json"].includes(format) ? format : "text";
      target.loggingState.textContent = target.loggingLevel.value + " / " + target.loggingFormat.value;
      setFormDisabled(target.loggingForm, !configUpdateAvailable);
      syncLoggingControls();
    }

    function renderConfig(result) {
      if (!result.ok) {
        target.dnsListen.textContent = "--";
        target.adminListen.textContent = "--";
        target.upstreamCount.textContent = "Unavailable";
        target.upstreamBody.textContent = "";
        target.upstreamBody.appendChild(emptyRow(6, "Config API unavailable."));
        target.dnssecState.textContent = "unavailable";
        setFormDisabled(target.upstreamForm, true);
        setFormDisabled(target.dnssecForm, true);
        setFormDisabled(target.cacheForm, true);
        setFormDisabled(target.blockingResponseForm, true);
        setFormDisabled(target.loggingForm, true);
        return;
      }

      const data = result.data || {};
      setText(target.dnsListen, pick(data, [
        "dns_listen", "dnsListen", "dns_address", "dnsAddress", "listen_dns", "listenDNS", "dns.listen", "server.dns_listen", "server.dnsListen"
      ]));
      setText(target.adminListen, pick(data, [
        "admin_listen", "adminListen", "admin_address", "adminAddress", "listen_admin", "listenAdmin", "admin.listen", "server.admin_listen", "server.adminListen"
      ]));
      currentUpstreams = renderUpstreamRows(listFrom(pick(data, [
        "upstreams", "upstream_resolvers", "upstreamResolvers", "resolvers", "dns_upstreams", "dnsUpstreams", "dns.upstreams"
      ])), target.upstreamCount, target.upstreamBody, true);
      resetUpstreamForm();
      setFormDisabled(target.upstreamForm, !configUpdateAvailable);
      renderDNSSEC(data);
      renderCache(data);
      renderBlockingResponse(data);
      renderLogging(data);
    }

    function renderAPIKeys(result) {
      target.apiKeyBody.textContent = "";
      setAPIKeyMessage("");
      if (!result.ok) {
        currentAPIKeys = [];
        apiKeysAvailable = false;
        target.apiKeyStatus.textContent = "Unavailable: " + displayValue(result.error);
        target.apiKeyBody.appendChild(emptyRow(7, "API key management is unavailable."));
        setFormDisabled(target.apiKeyForm, true);
        return;
      }

      currentAPIKeys = normalizeAPIKeys(result.data);
      apiKeysAvailable = true;
      target.apiKeyStatus.textContent = currentAPIKeys.length + " keys";
      setFormDisabled(target.apiKeyForm, false);

      if (!currentAPIKeys.length) {
        target.apiKeyBody.appendChild(emptyRow(7, "No API keys created."));
        return;
      }

      for (const key of currentAPIKeys) {
        const id = pick(key, ["id"]);
        const revokedAt = pick(key, ["revoked_at", "revokedAt"]);
        const disabled = Boolean(pick(key, ["disabled"])) || Boolean(revokedAt);
        const tr = document.createElement("tr");
        tr.appendChild(cell(pick(key, ["name"])));
        tr.appendChild(cell(pick(key, ["prefix"])));
        tr.appendChild(cell(pick(key, ["last4", "last_4", "lastFour"])));
        tr.appendChild(cell(formatTime(pick(key, ["created_at", "createdAt"]))));
        tr.appendChild(cell(formatTime(pick(key, ["last_used_at", "lastUsedAt"]))));
        const status = document.createElement("td");
        status.className = "status-cell";
        status.appendChild(pill(disabled ? "revoked" : "active", disabled ? "drop" : "allow"));
        tr.appendChild(status);
        const actions = document.createElement("td");
        if (disabled) {
          actions.textContent = "--";
        } else {
          const actionWrap = document.createElement("div");
          actionWrap.className = "table-actions";
          actionWrap.appendChild(actionButton("Revoke", "revoke", id, "danger"));
          actions.appendChild(actionWrap);
        }
        tr.appendChild(actions);
        target.apiKeyBody.appendChild(tr);
      }
    }

    async function refresh() {
      const [config, keys] = await Promise.all([
        fetchOptionalJSON("/api/config"),
        fetchOptionalJSON("/api/api-keys")
      ]);
      renderConfig(config);
      renderAPIKeys(keys);
      setUpdatedStatus("Settings / API Keys");
    }

    function upstreamFormPayload() {
      return {
        name: target.upstreamName.value.trim(),
        address: target.upstreamAddress.value.trim(),
        protocol: target.upstreamProtocol.value.trim() || "udp",
        tls_server_name: target.upstreamTLSServerName.value.trim(),
        enabled: target.upstreamEnabled.checked
      };
    }

    function upstreamConfigPayload(upstreams) {
      return upstreams.map(upstream => ({
        name: upstream.name || "",
        address: upstream.address || "",
        protocol: upstream.protocol || "udp",
        tls_server_name: upstream.tls_server_name || "",
        enabled: Boolean(upstream.enabled)
      }));
    }

    async function saveUpstreams(upstreams) {
      setUpstreamMessage("");
      const result = await fetchJSON("/api/config", {
        method: "PUT",
        headers: {"content-type": "application/json"},
        body: JSON.stringify({dns: {resolvers: upstreamConfigPayload(upstreams)}})
      });
      renderConfig({ok: true, data: result.config || {}});
      const status = result.restart_required
        ? "Upstream resolver config saved. Process restart required."
        : "Upstream resolver config applied immediately.";
      setUpstreamMessage(status, false);
      setUpdated(status);
    }

    async function saveDNSSEC(event) {
      event.preventDefault();
      const mode = target.dnssecMode.value === "upstream" ? "upstream" : "off";
      setFormDisabled(target.dnssecForm, true);
      setDNSSECMessage("Saving DNSSEC settings...");
      try {
        const result = await fetchJSON("/api/config", {
          method: "PUT",
          headers: {"content-type": "application/json"},
          body: JSON.stringify({dns: {dnssec: {enabled: mode === "upstream", mode: mode}}})
        });
        renderConfig({ok: true, data: result.config || {}});
        const status = result.restart_required
          ? "DNSSEC config saved. Process restart required."
          : "DNSSEC config applied through DNS hot reload.";
        setDNSSECMessage(status, false);
        setUpdated(status);
      } catch (err) {
        if (err.message === "config_update_unavailable") {
          configUpdateAvailable = false;
        }
        setDNSSECMessage("DNSSEC update failed: " + err.message, true);
      } finally {
        setFormDisabled(target.dnssecForm, !configUpdateAvailable);
      }
    }

    async function saveCache(event) {
      event.preventDefault();
      const successTTL = Number(target.cacheSuccessTTL.value);
      const denialTTL = Number(target.cacheDenialTTL.value);
      const successCapacity = Number(target.cacheSuccessCapacity.value);
      const denialCapacity = Number(target.cacheDenialCapacity.value);
      const prefetchAmount = Number(target.cachePrefetchAmount.value);
      const prefetchDuration = Number(target.cachePrefetchDuration.value);
      const prefetchPercent = Number(target.cachePrefetchPercent.value);
      setFormDisabled(target.cacheForm, true);
      setCacheMessage("Saving DNS cache settings...");
      try {
        const result = await fetchJSON("/api/config", {
          method: "PUT",
          headers: {"content-type": "application/json"},
          body: JSON.stringify({
            dns: {
              cache_success_ttl: successTTL,
              cache_denial_ttl: denialTTL,
              cache_success_capacity: successCapacity,
              cache_denial_capacity: denialCapacity,
              cache_prefetch_amount: prefetchAmount,
              cache_prefetch_duration: prefetchDuration,
              cache_prefetch_percent: prefetchPercent
            }
          })
        });
        renderConfig({ok: true, data: result.config || {}});
        const status = result.restart_required
          ? "DNS cache config saved. Process restart required."
          : "DNS cache config applied through DNS hot reload.";
        setCacheMessage(status, false);
        setUpdated(status);
      } catch (err) {
        if (err.message === "config_update_unavailable") {
          configUpdateAvailable = false;
        }
        setCacheMessage("DNS cache update failed: " + err.message, true);
      } finally {
        setFormDisabled(target.cacheForm, !configUpdateAvailable);
      }
    }

    async function saveBlockingResponse(event) {
      event.preventDefault();
      setFormDisabled(target.blockingResponseForm, true);
      setBlockingResponseMessage("Saving blocking response...");
      try {
        const result = await fetchJSON("/api/config", {
          method: "PUT",
          headers: {"content-type": "application/json"},
          body: JSON.stringify({blocking: {response: target.blockingResponseMode.value}})
        });
        renderConfig({ok: true, data: result.config || {}});
        const status = result.restart_required
          ? "Blocking response saved. Restart required for all changes."
          : "Blocking response applied.";
        setBlockingResponseMessage(status, false);
        setUpdated(status);
      } catch (err) {
        if (err.message === "config_update_unavailable") {
          configUpdateAvailable = false;
        }
        setBlockingResponseMessage("Blocking response update failed: " + err.message, true);
      } finally {
        setFormDisabled(target.blockingResponseForm, !configUpdateAvailable);
      }
    }

    async function saveLogging(event) {
      event.preventDefault();
      setFormDisabled(target.loggingForm, true);
      setLoggingMessage("Saving logging settings...");
      try {
        const result = await fetchJSON("/api/config", {
          method: "PUT",
          headers: {"content-type": "application/json"},
          body: JSON.stringify({
            logging: {
              level: target.loggingLevel.value,
              format: target.loggingFormat.value
            }
          })
        });
        renderConfig({ok: true, data: result.config || {}});
        const status = result.restart_required
          ? "Logging saved. Restart required for DNS logging changes."
          : "Logging applied.";
        setLoggingMessage(status, false);
        setUpdated(status);
      } catch (err) {
        if (err.message === "config_update_unavailable") {
          configUpdateAvailable = false;
        }
        setLoggingMessage("Logging update failed: " + err.message, true);
      } finally {
        setFormDisabled(target.loggingForm, !configUpdateAvailable);
        syncLoggingControls();
      }
    }

    async function submitUpstream(event) {
      event.preventDefault();
      const next = currentUpstreams.slice();
      const payload = upstreamFormPayload();
      const index = target.upstreamIndex.value === "" ? -1 : Number(target.upstreamIndex.value);
      if (index >= 0 && index < next.length) {
        next[index] = payload;
      } else {
        next.push(payload);
      }
      setFormDisabled(target.upstreamForm, true);
      try {
        await saveUpstreams(next);
      } catch (err) {
        if (err.message === "config_update_unavailable") {
          configUpdateAvailable = false;
        }
        setUpstreamMessage("Upstream resolver update failed: " + err.message, true);
      } finally {
        setFormDisabled(target.upstreamForm, !configUpdateAvailable);
      }
    }

    async function handleUpstreamAction(button) {
      const index = Number(button.dataset.id);
      if (!Number.isInteger(index) || index < 0 || index >= currentUpstreams.length) {
        return;
      }
      const upstream = currentUpstreams[index];
      if (button.dataset.action === "edit-upstream") {
        target.upstreamIndex.value = String(index);
        target.upstreamName.value = upstream.name || "";
        target.upstreamAddress.value = upstream.address || "";
        target.upstreamProtocol.value = upstream.protocol || "udp";
        target.upstreamTLSServerName.value = upstream.tls_server_name || "";
        target.upstreamEnabled.checked = Boolean(upstream.enabled);
        target.upstreamSave.textContent = "Save resolver";
        target.upstreamCancel.classList.remove("hidden");
        target.upstreamName.focus();
        return;
      }

      const next = currentUpstreams.slice();
      if (button.dataset.action === "toggle-upstream") {
        next[index] = Object.assign({}, upstream, {enabled: !upstream.enabled});
      } else if (button.dataset.action === "delete-upstream") {
        next.splice(index, 1);
      } else {
        return;
      }

      button.disabled = true;
      try {
        await saveUpstreams(next);
      } catch (err) {
        if (err.message === "config_update_unavailable") {
          configUpdateAvailable = false;
        }
        setUpstreamMessage("Upstream resolver update failed: " + err.message, true);
        button.disabled = false;
      }
    }

    function apiKeyByID(id) {
      return currentAPIKeys.find(key => String(pick(key, ["id"])) === String(id));
    }

    async function createAPIKey(event) {
      event.preventDefault();
      if (!apiKeysAvailable) {
        setAPIKeyMessage("API key management is unavailable.", true);
        return;
      }
      const name = target.apiKeyName.value.trim();
      if (!name) {
        setAPIKeyMessage("Key name is required.", true);
        return;
      }

      target.apiKeyCreate.disabled = true;
      try {
        const created = await fetchJSON("/api/api-keys", {
          method: "POST",
          headers: {"content-type": "application/json"},
          body: JSON.stringify({name: name})
        });
        target.apiKeyName.value = "";
        renderAPIKeys(await fetchOptionalJSON("/api/api-keys"));
        setAPIKeyMessage("New API key: " + displayValue(pick(created || {}, ["key"])) + " Store it now; it will not be shown again.", false);
      } catch (err) {
        setAPIKeyMessage("API key create failed: " + err.message, true);
      } finally {
        target.apiKeyCreate.disabled = !apiKeysAvailable;
      }
    }

    async function handleAPIKeyAction(event) {
      const button = event.target.closest("button[data-action]");
      if (!button) {
        return;
      }
      const key = apiKeyByID(button.dataset.id);
      if (!key || !window.confirm("Revoke this API key?")) {
        return;
      }
      button.disabled = true;
      try {
        await fetchJSON("/api/api-keys/" + encodeURIComponent(pick(key, ["id"])), {method: "DELETE"});
        renderAPIKeys(await fetchOptionalJSON("/api/api-keys"));
        setAPIKeyMessage("API key revoked.", false);
      } catch (err) {
        setAPIKeyMessage("API key revoke failed: " + err.message, true);
        button.disabled = false;
      }
    }

    on(target.dnssecForm, "submit", saveDNSSEC);
    on(target.cacheForm, "submit", saveCache);
    on(target.blockingResponseForm, "submit", saveBlockingResponse);
    on(target.loggingForm, "submit", saveLogging);
    on(target.upstreamForm, "submit", submitUpstream);
    on(target.upstreamCancel, "click", () => {
      resetUpstreamForm();
      setUpstreamMessage("");
    });
    on(target.upstreamBody, "click", event => {
      const button = event.target.closest("button[data-action]");
      if (button) {
        handleUpstreamAction(button);
      }
    });
    on(target.apiKeyForm, "submit", createAPIKey);
    on(target.apiKeyBody, "click", handleAPIKeyAction);

    return {refresh};
  }
});
