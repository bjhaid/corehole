import {initAdminPage} from "../admin.js";
import {fetchJSON, fetchOptionalJSON} from "../lib/api.js";
import {on, required} from "../lib/dom.js";
import {actionButton, cell, configureTemplates, emptyRow, pill} from "../lib/elements.js";
import {bundledConfigValue, boolLabel, displayValue, formatTime, listFrom, pick} from "../lib/format.js";
import {setFormDisabled} from "../lib/forms.js";
import {groupAssignmentCell, loadGroupAssignments, normalizeFilterLists, normalizeGroups} from "../lib/filter-ui.js";

function pageFields() {
  return {
    form: required("#blocklist-form"),
    source: required("#blocklist-source"),
    sourceType: required("#blocklist-source-type"),
    kind: required("#blocklist-kind"),
    enabled: required("#blocklist-enabled"),
    bundledToggle: required("#bundled-toggle"),
    bundledNote: required("#bundled-note"),
    sourceStatus: required("#blocklist-source-status"),
    body: required("#blocklist-body")
  };
}

function listSource(list) {
  return pick(list, ["url", "path", "source"]) || "";
}

function updatePayloadForList(list, enabled) {
  const payload = {
    url: pick(list, ["url"]) || "",
    path: pick(list, ["path"]) || "",
    kind: pick(list, ["kind"]) || "deny",
    enabled: enabled,
    last_error: pick(list, ["last_error", "lastError"]) || ""
  };
  const lastUpdatedAt = pick(list, ["last_updated_at", "lastUpdatedAt"]);
  if (lastUpdatedAt) {
    payload.last_updated_at = lastUpdatedAt;
  }
  return payload;
}

initAdminPage({
  label: "Blocklists",
  init({refresh, setUpdated, setUpdatedStatus}) {
    const fields = pageFields();
    let currentConfig = {};
    let currentFilterLists = [];
    let currentGroups = [];
    let currentAssignments = new Map();
    let filterListsAvailable = false;
    let groupsAvailable = false;
    let configUpdateAvailable = true;

    configureTemplates({emptyRow: required("#template-empty-row")});

    function renderBundledState(data) {
      const bundled = bundledConfigValue(data);
      if (typeof bundled === "boolean") {
        fields.bundledNote.textContent = configUpdateAvailable
          ? "Config reports bundled default blocking as " + boolLabel(bundled) + "."
          : "Bundled default state is exposed, but config updates are unavailable.";
        fields.bundledToggle.disabled = !configUpdateAvailable;
        fields.bundledToggle.textContent = configUpdateAvailable ? (bundled ? "Disable" : "Enable") : "Read-only";
        return;
      }
      fields.bundledNote.textContent = "Bundled default state is not exposed by the config API.";
      fields.bundledToggle.disabled = true;
      fields.bundledToggle.textContent = "Unavailable";
    }

    function renderBlocklists(config, filterResult) {
      const configuredPaths = listFrom(pick(config, [
        "blocklist_paths", "blocklistPaths", "blocklists", "blocking.blocklists"
      ]));
      const filterLists = filterResult.ok ? normalizeFilterLists(filterResult.data) : [];
      currentFilterLists = filterLists;
      filterListsAvailable = filterResult.ok;
      setFormDisabled(fields.form, !filterListsAvailable);

      fields.body.textContent = "";
      const rows = [];
      const seenSources = new Set();
      for (const list of filterLists) {
        const source = listSource(list);
        if (source) {
          seenSources.add(source);
        }
        rows.push({type: "filter", list: list});
      }
      for (const path of configuredPaths) {
        if (!seenSources.has(path)) {
          rows.push({type: "config", path: path});
        }
      }

      fields.sourceStatus.textContent = filterListsAvailable
        ? filterLists.length + " subscribed, " + configuredPaths.length + " configured"
        : "Subscribed lists unavailable: " + displayValue(filterResult.error);
      renderBundledState(config);

      if (!rows.length) {
        const text = filterListsAvailable ? "No configured or subscribed blocklists reported." : "Blocklist API unavailable and no configured paths reported.";
        fields.body.appendChild(emptyRow(7, text));
        return;
      }

      for (const row of rows) {
        const tr = document.createElement("tr");
        if (row.type === "config") {
          const sourceCell = cell(row.path);
          sourceCell.className = "source-cell";
          tr.appendChild(sourceCell);
          tr.appendChild(cell("deny"));
          const status = document.createElement("td");
          status.className = "status-cell";
          status.appendChild(pill("configured", ""));
          tr.appendChild(status);
          tr.appendChild(cell("--"));
          tr.appendChild(cell("--"));
          tr.appendChild(cell("--"));
          tr.appendChild(cell("read-only config path"));
          fields.body.appendChild(tr);
          continue;
        }

        const list = row.list;
        const id = pick(list, ["id"]);
        const sourceCell = cell(listSource(list));
        sourceCell.className = "source-cell";
        tr.appendChild(sourceCell);
        tr.appendChild(cell(pick(list, ["kind"]) || "deny"));
        const status = document.createElement("td");
        status.className = "status-cell";
        status.appendChild(pill(boolLabel(Boolean(pick(list, ["enabled"]))), pick(list, ["enabled"]) ? "allow" : "drop"));
        tr.appendChild(status);
        tr.appendChild(cell(formatTime(pick(list, ["last_updated_at", "lastUpdatedAt"]))));
        tr.appendChild(cell(pick(list, ["last_error", "lastError"]) || "--"));
        tr.appendChild(groupAssignmentCell("lists", id, currentAssignments.get(String(id)), "global", currentGroups, groupsAvailable));
        const actions = document.createElement("td");
        const actionWrap = document.createElement("div");
        actionWrap.className = "table-actions";
        actionWrap.appendChild(actionButton("Refresh", "refresh", id, "secondary"));
        actionWrap.appendChild(actionButton(pick(list, ["enabled"]) ? "Disable" : "Enable", "toggle", id, "secondary"));
        actionWrap.appendChild(actionButton("Delete", "delete", id, "danger"));
        actions.appendChild(actionWrap);
        tr.appendChild(actions);
        fields.body.appendChild(tr);
      }
    }

    function filterListByID(id) {
      return currentFilterLists.find(list => String(pick(list, ["id"])) === String(id));
    }

    async function refreshPage() {
      const [config, filterLists, groups] = await Promise.all([
        fetchOptionalJSON("/api/config"),
        fetchOptionalJSON("/api/filter/lists"),
        fetchOptionalJSON("/api/filter/groups")
      ]);
      if (config.ok) {
        currentConfig = config.data || {};
      }
      currentGroups = groups.ok ? normalizeGroups(groups.data) : [];
      groupsAvailable = groups.ok;
      const filterListItems = filterLists.ok ? normalizeFilterLists(filterLists.data) : [];
      currentAssignments = filterLists.ok ? await loadGroupAssignments("lists", filterListItems) : new Map();
      renderBlocklists(config.ok ? config.data || {} : currentConfig, filterLists);
      setUpdatedStatus("Blocklists");
    }

    async function toggleBundledBlocking() {
      const bundled = bundledConfigValue(currentConfig);
      if (typeof bundled !== "boolean") {
        return;
      }
      fields.bundledToggle.disabled = true;
      try {
        await fetchJSON("/api/config", {
          method: "PUT",
          headers: {"content-type": "application/json"},
          body: JSON.stringify({blocking: {bundled: !bundled}})
        });
        await refresh();
        setUpdated("Bundled default saved to config. No reload endpoint is exposed.");
      } catch (err) {
        setUpdated("Bundled default update failed: " + err.message);
        if (err.message === "config_update_unavailable") {
          configUpdateAvailable = false;
        }
        renderBundledState(currentConfig);
      }
    }

    async function createBlocklist(event) {
      event.preventDefault();
      if (!filterListsAvailable) {
        setUpdated("Blocklist API unavailable.");
        return;
      }
      const source = fields.source.value.trim();
      if (!source) {
        return;
      }
      const payload = {
        kind: fields.kind.value,
        enabled: fields.enabled.checked
      };
      if (fields.sourceType.value === "path") {
        payload.path = source;
      } else {
        payload.url = source;
      }
      try {
        const created = await fetchJSON("/api/filter/lists", {
          method: "POST",
          headers: {"content-type": "application/json"},
          body: JSON.stringify(payload)
        });
        let refreshError = null;
        try {
          await fetchJSON("/api/filter/lists/" + encodeURIComponent(pick(created, ["id"])) + "/refresh", {method: "POST"});
        } catch (err) {
          refreshError = err;
        }
        fields.source.value = "";
        fields.enabled.checked = true;
        await refresh();
        if (refreshError) {
          setUpdated("Blocklist refresh failed: " + refreshError.message);
        }
      } catch (err) {
        setUpdated("Blocklist create failed: " + err.message);
      }
    }

    async function handleGroupAssignmentAction(button) {
      const action = button.dataset.action;
      if (action !== "assign-group" && action !== "remove-group") {
        return false;
      }
      const resource = button.dataset.resource;
      const ownerID = button.dataset.id;
      if (!resource || !ownerID) {
        return true;
      }
      let groupID = button.dataset.groupId;
      if (action === "assign-group") {
        const select = button.parentElement ? button.parentElement.querySelector("select[data-role='group-select']") : null;
        groupID = select ? select.value : "";
      }
      if (!groupID) {
        setUpdated("Choose a group first.");
        return true;
      }
      button.disabled = true;
      try {
        const path = "/api/filter/" + resource + "/" + encodeURIComponent(ownerID) + "/groups";
        if (action === "assign-group") {
          await fetchJSON(path, {
            method: "POST",
            headers: {"content-type": "application/json"},
            body: JSON.stringify({group_id: Number(groupID)})
          });
        } else {
          await fetchJSON(path + "/" + encodeURIComponent(groupID), {method: "DELETE"});
        }
        await refresh();
        setUpdated("Group assignment updated.");
      } catch (err) {
        setUpdated("Group assignment failed: " + err.message);
        button.disabled = false;
      }
      return true;
    }

    async function handleBlocklistAction(event) {
      const button = event.target.closest("button[data-action]");
      if (!button) {
        return;
      }
      if (await handleGroupAssignmentAction(button)) {
        return;
      }
      const list = filterListByID(button.dataset.id);
      if (!list) {
        return;
      }
      const id = pick(list, ["id"]);
      button.disabled = true;
      try {
        if (button.dataset.action === "toggle") {
          await fetchJSON("/api/filter/lists/" + encodeURIComponent(id), {
            method: "PUT",
            headers: {"content-type": "application/json"},
            body: JSON.stringify(updatePayloadForList(list, !Boolean(pick(list, ["enabled"]))))
          });
        } else if (button.dataset.action === "refresh") {
          await fetchJSON("/api/filter/lists/" + encodeURIComponent(id) + "/refresh", {method: "POST"});
        } else if (button.dataset.action === "delete") {
          if (!window.confirm("Delete this blocklist?")) {
            button.disabled = false;
            return;
          }
          await fetchJSON("/api/filter/lists/" + encodeURIComponent(id), {method: "DELETE"});
        }
        await refresh();
      } catch (err) {
        if (button.dataset.action === "refresh") {
          try {
            await refresh();
          } catch (_) {}
        }
        setUpdated("Blocklist update failed: " + err.message);
        button.disabled = false;
      }
    }

    on(fields.bundledToggle, "click", toggleBundledBlocking);
    on(fields.form, "submit", createBlocklist);
    on(fields.body, "click", handleBlocklistAction);

    return {refresh: refreshPage};
  }
});
