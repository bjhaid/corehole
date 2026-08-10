import {initAdminPage} from "../admin.js";
import {fetchJSON, fetchOptionalJSON} from "../lib/api.js";
import {on, required} from "../lib/dom.js";
import {actionButton, cell, configureTemplates, emptyRow, pill} from "../lib/elements.js";
import {boolLabel, displayValue, pick} from "../lib/format.js";
import {setFormDisabled} from "../lib/forms.js";
import {
  groupAssignmentCell,
  loadGroupAssignments,
  normalizeClients,
  normalizeClientSuggestions,
  normalizeGroups
} from "../lib/filter-ui.js";

function fields() {
  return {
    clientStatus: required("#client-status"),
    clientForm: required("#client-form"),
    clientID: required("#client-id"),
    clientAddress: required("#client-address"),
    clientSuggestions: required("#client-suggestions"),
    clientName: required("#client-name"),
    clientComment: required("#client-comment"),
    clientEnabled: required("#client-enabled"),
    clientSave: required("#client-save"),
    clientCancel: required("#client-cancel"),
    clientBody: required("#client-body"),
    groupStatus: required("#group-status"),
    groupForm: required("#group-form"),
    groupID: required("#group-id"),
    groupName: required("#group-name"),
    groupComment: required("#group-comment"),
    groupEnabled: required("#group-enabled"),
    groupSave: required("#group-save"),
    groupCancel: required("#group-cancel"),
    groupBody: required("#group-body")
  };
}

function suggestionAddress(suggestion) {
  if (typeof suggestion === "string") {
    return suggestion.trim();
  }
  return String(pick(suggestion, ["address", "client_ip", "clientIP", "ip"]) || "").trim();
}

initAdminPage({
  label: "Clients / Groups",
  init({refresh, setUpdated, setUpdatedStatus}) {
    const target = fields();
    let currentClients = [];
    let currentGroups = [];
    let currentAssignments = new Map();
    let clientsAvailable = false;
    let groupsAvailable = false;

    configureTemplates({emptyRow: required("#template-empty-row")});

    function resetClientForm() {
      target.clientForm.reset();
      target.clientID.value = "";
      target.clientEnabled.checked = true;
      target.clientSave.textContent = "Add client";
      target.clientCancel.classList.add("hidden");
    }

    function resetGroupForm() {
      target.groupForm.reset();
      target.groupID.value = "";
      target.groupEnabled.checked = true;
      target.groupSave.textContent = "Add group";
      target.groupCancel.classList.add("hidden");
    }

    function clientByID(id) {
      return currentClients.find(client => String(pick(client, ["id"])) === String(id));
    }

    function groupByID(id) {
      return currentGroups.find(group => String(pick(group, ["id"])) === String(id));
    }

    function existingClientForAddress(address, excludeID) {
      const key = String(address || "").trim().toLowerCase();
      return currentClients.find(client => {
        if (String(pick(client, ["id"])) === String(excludeID || "")) {
          return false;
        }
        return String(pick(client, ["address"]) || "").trim().toLowerCase() === key;
      });
    }

    function clientPayloadFromRecord(client, enabled) {
      return {
        address: pick(client, ["address"]) || "",
        name: pick(client, ["name"]) || "",
        comment: pick(client, ["comment"]) || "",
        enabled: enabled
      };
    }

    function groupPayloadFromRecord(group, enabled) {
      return {
        name: pick(group, ["name"]) || "",
        comment: pick(group, ["comment"]) || "",
        enabled: enabled
      };
    }

    function renderClientSuggestions(result) {
      target.clientSuggestions.textContent = "";
      if (!result || !result.ok) {
        return;
      }
      const configuredAddresses = new Set(currentClients
        .map(client => String(pick(client, ["address"]) || "").trim().toLowerCase())
        .filter(Boolean));
      const seen = new Set();
      for (const suggestion of normalizeClientSuggestions(result.data)) {
        const address = suggestionAddress(suggestion);
        const key = address.toLowerCase();
        if (!address || seen.has(key) || configuredAddresses.has(key)) {
          continue;
        }
        seen.add(key);
        const option = document.createElement("option");
        option.value = address;
        const count = Number(pick(suggestion, ["count"]));
        if (Number.isFinite(count) && count > 0) {
          option.label = count + " queries";
        }
        target.clientSuggestions.appendChild(option);
      }
    }

    function renderClients(result) {
      target.clientBody.textContent = "";
      if (!result.ok) {
        currentClients = [];
        clientsAvailable = false;
        target.clientStatus.textContent = "Unavailable: " + displayValue(result.error);
        target.clientBody.appendChild(emptyRow(6, "Clients API unavailable."));
        setFormDisabled(target.clientForm, true);
        return;
      }

      currentClients = normalizeClients(result.data);
      clientsAvailable = true;
      target.clientStatus.textContent = currentClients.length + " clients";
      setFormDisabled(target.clientForm, false);
      target.clientCancel.disabled = false;

      if (!currentClients.length) {
        target.clientBody.appendChild(emptyRow(6, "No clients configured."));
        return;
      }

      for (const client of currentClients) {
        const id = pick(client, ["id"]);
        const enabled = Boolean(pick(client, ["enabled"]));
        const tr = document.createElement("tr");
        tr.appendChild(cell(pick(client, ["address"])));
        tr.appendChild(cell(pick(client, ["name"])));
        const status = document.createElement("td");
        status.className = "status-cell";
        status.appendChild(pill(boolLabel(enabled), enabled ? "allow" : "drop"));
        tr.appendChild(status);
        tr.appendChild(cell(pick(client, ["comment"]) || "--"));
        tr.appendChild(groupAssignmentCell("clients", id, currentAssignments.get(String(id)), "none", currentGroups, groupsAvailable));
        const actions = document.createElement("td");
        const actionWrap = document.createElement("div");
        actionWrap.className = "table-actions";
        actionWrap.appendChild(actionButton("Edit", "edit", id, "secondary"));
        actionWrap.appendChild(actionButton(enabled ? "Disable" : "Enable", "toggle", id, "secondary"));
        actionWrap.appendChild(actionButton("Delete", "delete", id, "danger"));
        actions.appendChild(actionWrap);
        tr.appendChild(actions);
        target.clientBody.appendChild(tr);
      }
    }

    function renderGroups(result) {
      target.groupBody.textContent = "";
      if (!result.ok) {
        currentGroups = [];
        groupsAvailable = false;
        target.groupStatus.textContent = "Unavailable: " + displayValue(result.error);
        target.groupBody.appendChild(emptyRow(4, "Groups API unavailable."));
        setFormDisabled(target.groupForm, true);
        return;
      }

      currentGroups = normalizeGroups(result.data);
      groupsAvailable = true;
      target.groupStatus.textContent = currentGroups.length + " groups";
      setFormDisabled(target.groupForm, false);
      target.groupCancel.disabled = false;

      if (!currentGroups.length) {
        target.groupBody.appendChild(emptyRow(4, "No groups configured."));
        return;
      }

      for (const group of currentGroups) {
        const id = pick(group, ["id"]);
        const enabled = Boolean(pick(group, ["enabled"]));
        const tr = document.createElement("tr");
        tr.appendChild(cell(pick(group, ["name"])));
        const status = document.createElement("td");
        status.className = "status-cell";
        status.appendChild(pill(boolLabel(enabled), enabled ? "allow" : "drop"));
        tr.appendChild(status);
        tr.appendChild(cell(pick(group, ["comment"]) || "--"));
        const actions = document.createElement("td");
        const actionWrap = document.createElement("div");
        actionWrap.className = "table-actions";
        actionWrap.appendChild(actionButton("Edit", "edit", id, "secondary"));
        actionWrap.appendChild(actionButton(enabled ? "Disable" : "Enable", "toggle", id, "secondary"));
        actionWrap.appendChild(actionButton("Delete", "delete", id, "danger"));
        actions.appendChild(actionWrap);
        tr.appendChild(actions);
        target.groupBody.appendChild(tr);
      }
    }

    async function refreshPage() {
      const [clients, groups, suggestions] = await Promise.all([
        fetchOptionalJSON("/api/filter/clients"),
        fetchOptionalJSON("/api/filter/groups"),
        fetchOptionalJSON("/api/filter/clients/suggestions")
      ]);
      currentGroups = groups.ok ? normalizeGroups(groups.data) : [];
      groupsAvailable = groups.ok;
      const clientItems = clients.ok ? normalizeClients(clients.data) : [];
      currentAssignments = clients.ok ? await loadGroupAssignments("clients", clientItems) : new Map();
      renderGroups(groups);
      renderClients(clients);
      renderClientSuggestions(suggestions);
      setUpdatedStatus("Clients / Groups");
    }

    async function handleGroupAssignmentAction(button) {
      const action = button.dataset.action;
      if (action !== "assign-group" && action !== "remove-group") {
        return false;
      }
      const ownerID = button.dataset.id;
      let groupID = button.dataset.groupId;
      if (action === "assign-group") {
        const select = button.parentElement ? button.parentElement.querySelector("select[data-role='group-select']") : null;
        groupID = select ? select.value : "";
      }
      if (!ownerID || !groupID) {
        setUpdated("Choose a group first.");
        return true;
      }
      button.disabled = true;
      try {
        const path = "/api/filter/clients/" + encodeURIComponent(ownerID) + "/groups";
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

    function clientPayloadFromForm() {
      const address = target.clientAddress.value.trim();
      const name = target.clientName.value.trim();
      if (!address) {
        throw new Error("address is required");
      }
      if (!name) {
        throw new Error("name is required");
      }
      const duplicate = existingClientForAddress(address, target.clientID.value);
      if (duplicate) {
        throw new Error("address already belongs to " + displayValue(pick(duplicate, ["name"]) || pick(duplicate, ["address"])));
      }
      return {
        address: address,
        name: name,
        comment: target.clientComment.value.trim(),
        enabled: target.clientEnabled.checked
      };
    }

    function groupPayloadFromForm() {
      const name = target.groupName.value.trim();
      if (!name) {
        throw new Error("name is required");
      }
      return {
        name: name,
        comment: target.groupComment.value.trim(),
        enabled: target.groupEnabled.checked
      };
    }

    function editClient(client) {
      target.clientID.value = pick(client, ["id"]) || "";
      target.clientAddress.value = pick(client, ["address"]) || "";
      target.clientName.value = pick(client, ["name"]) || "";
      target.clientComment.value = pick(client, ["comment"]) || "";
      target.clientEnabled.checked = Boolean(pick(client, ["enabled"]));
      target.clientSave.textContent = "Save client";
      target.clientCancel.classList.remove("hidden");
      setUpdated("Editing client " + displayValue(pick(client, ["address"])) + ".");
      target.clientAddress.focus();
    }

    function editGroup(group) {
      target.groupID.value = pick(group, ["id"]) || "";
      target.groupName.value = pick(group, ["name"]) || "";
      target.groupComment.value = pick(group, ["comment"]) || "";
      target.groupEnabled.checked = Boolean(pick(group, ["enabled"]));
      target.groupSave.textContent = "Save group";
      target.groupCancel.classList.remove("hidden");
      setUpdated("Editing group " + displayValue(pick(group, ["name"])) + ".");
      target.groupName.focus();
    }

    async function saveClient(event) {
      event.preventDefault();
      if (!clientsAvailable) {
        setUpdated("Clients API unavailable.");
        return;
      }
      let payload;
      try {
        payload = clientPayloadFromForm();
      } catch (err) {
        setUpdated("Client validation failed: " + err.message);
        return;
      }
      const id = target.clientID.value;
      target.clientSave.disabled = true;
      try {
        await fetchJSON(id ? "/api/filter/clients/" + encodeURIComponent(id) : "/api/filter/clients", {
          method: id ? "PUT" : "POST",
          headers: {"content-type": "application/json"},
          body: JSON.stringify(payload)
        });
        resetClientForm();
        await refresh();
        setUpdated(id ? "Client saved." : "Client added.");
      } catch (err) {
        setUpdated("Client save failed: " + err.message);
        target.clientSave.disabled = false;
      }
    }

    async function saveGroup(event) {
      event.preventDefault();
      if (!groupsAvailable) {
        setUpdated("Groups API unavailable.");
        return;
      }
      let payload;
      try {
        payload = groupPayloadFromForm();
      } catch (err) {
        setUpdated("Group validation failed: " + err.message);
        return;
      }
      const id = target.groupID.value;
      target.groupSave.disabled = true;
      try {
        await fetchJSON(id ? "/api/filter/groups/" + encodeURIComponent(id) : "/api/filter/groups", {
          method: id ? "PUT" : "POST",
          headers: {"content-type": "application/json"},
          body: JSON.stringify(payload)
        });
        resetGroupForm();
        await refresh();
        setUpdated(id ? "Group saved." : "Group added.");
      } catch (err) {
        setUpdated("Group save failed: " + err.message);
        target.groupSave.disabled = false;
      }
    }

    async function handleClientAction(event) {
      const button = event.target.closest("button[data-action]");
      if (!button) {
        return;
      }
      if (await handleGroupAssignmentAction(button)) {
        return;
      }
      const client = clientByID(button.dataset.id);
      if (!client) {
        return;
      }
      const id = pick(client, ["id"]);
      if (button.dataset.action === "edit") {
        editClient(client);
        return;
      }
      button.disabled = true;
      try {
        if (button.dataset.action === "toggle") {
          await fetchJSON("/api/filter/clients/" + encodeURIComponent(id), {
            method: "PUT",
            headers: {"content-type": "application/json"},
            body: JSON.stringify(clientPayloadFromRecord(client, !Boolean(pick(client, ["enabled"]))))
          });
        } else if (button.dataset.action === "delete") {
          if (!window.confirm("Delete this client?")) {
            button.disabled = false;
            return;
          }
          await fetchJSON("/api/filter/clients/" + encodeURIComponent(id), {method: "DELETE"});
          if (String(target.clientID.value) === String(id)) {
            resetClientForm();
          }
        }
        await refresh();
        setUpdated("Client updated.");
      } catch (err) {
        setUpdated("Client update failed: " + err.message);
        button.disabled = false;
      }
    }

    async function handleGroupAction(event) {
      const button = event.target.closest("button[data-action]");
      if (!button) {
        return;
      }
      const group = groupByID(button.dataset.id);
      if (!group) {
        return;
      }
      const id = pick(group, ["id"]);
      if (button.dataset.action === "edit") {
        editGroup(group);
        return;
      }
      button.disabled = true;
      try {
        if (button.dataset.action === "toggle") {
          await fetchJSON("/api/filter/groups/" + encodeURIComponent(id), {
            method: "PUT",
            headers: {"content-type": "application/json"},
            body: JSON.stringify(groupPayloadFromRecord(group, !Boolean(pick(group, ["enabled"]))))
          });
        } else if (button.dataset.action === "delete") {
          if (!window.confirm("Delete this group?")) {
            button.disabled = false;
            return;
          }
          await fetchJSON("/api/filter/groups/" + encodeURIComponent(id), {method: "DELETE"});
          if (String(target.groupID.value) === String(id)) {
            resetGroupForm();
          }
        }
        await refresh();
        setUpdated("Group updated.");
      } catch (err) {
        setUpdated("Group update failed: " + err.message);
        button.disabled = false;
      }
    }

    on(target.clientForm, "submit", saveClient);
    on(target.clientCancel, "click", resetClientForm);
    on(target.clientBody, "click", handleClientAction);
    on(target.groupForm, "submit", saveGroup);
    on(target.groupCancel, "click", resetGroupForm);
    on(target.groupBody, "click", handleGroupAction);

    return {refresh: refreshPage};
  }
});
