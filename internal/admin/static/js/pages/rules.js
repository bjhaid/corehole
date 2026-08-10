import {initAdminPage} from "../admin.js";
import {fetchJSON, fetchOptionalJSON} from "../lib/api.js";
import {on, required} from "../lib/dom.js";
import {actionButton, cell, configureTemplates, emptyRow, pill} from "../lib/elements.js";
import {boolLabel, displayValue, pick} from "../lib/format.js";
import {setFormDisabled} from "../lib/forms.js";
import {groupAssignmentCell, loadGroupAssignments, normalizeGroups, normalizeRules} from "../lib/filter-ui.js";

function fields() {
  return {
    status: required("#rule-status"),
    form: required("#rule-form"),
    id: required("#rule-id"),
    pattern: required("#rule-pattern"),
    kind: required("#rule-kind"),
    matchType: required("#rule-match-type"),
    comment: required("#rule-comment"),
    enabled: required("#rule-enabled"),
    save: required("#rule-save"),
    cancel: required("#rule-cancel"),
    body: required("#rule-body")
  };
}

initAdminPage({
  label: "Rules",
  init({refresh, setUpdated, setUpdatedStatus}) {
    const target = fields();
    let currentRules = [];
    let currentGroups = [];
    let currentAssignments = new Map();
    let rulesAvailable = false;
    let groupsAvailable = false;

    configureTemplates({emptyRow: required("#template-empty-row")});

    function resetForm() {
      target.form.reset();
      target.id.value = "";
      target.kind.value = "deny";
      target.matchType.value = "exact";
      target.enabled.checked = true;
      target.save.textContent = "Add rule";
      target.cancel.classList.add("hidden");
    }

    function ruleByID(id) {
      return currentRules.find(rule => String(pick(rule, ["id"])) === String(id));
    }

    function payloadFromRecord(rule, enabled) {
      return {
        pattern: pick(rule, ["pattern"]) || "",
        kind: pick(rule, ["kind"]) || "deny",
        match_type: pick(rule, ["match_type", "matchType"]) || "exact",
        enabled: enabled,
        comment: pick(rule, ["comment"]) || ""
      };
    }

    function renderRules(result) {
      target.body.textContent = "";
      if (!result.ok) {
        currentRules = [];
        rulesAvailable = false;
        target.status.textContent = "Unavailable: " + displayValue(result.error);
        target.body.appendChild(emptyRow(7, "Rules API unavailable."));
        setFormDisabled(target.form, true);
        return;
      }

      currentRules = normalizeRules(result.data);
      rulesAvailable = true;
      target.status.textContent = currentRules.length + " rules";
      setFormDisabled(target.form, false);
      target.cancel.disabled = false;

      if (!currentRules.length) {
        target.body.appendChild(emptyRow(7, "No allow or deny rules configured."));
        return;
      }

      for (const rule of currentRules) {
        const id = pick(rule, ["id"]);
        const enabled = Boolean(pick(rule, ["enabled"]));
        const kind = pick(rule, ["kind"]) || "deny";
        const tr = document.createElement("tr");
        tr.appendChild(cell(pick(rule, ["pattern"])));
        const kindCell = document.createElement("td");
        kindCell.className = "status-cell";
        kindCell.appendChild(pill(kind, kind === "allow" ? "allow" : "block"));
        tr.appendChild(kindCell);
        tr.appendChild(cell(pick(rule, ["match_type", "matchType"]) || "exact"));
        const status = document.createElement("td");
        status.className = "status-cell";
        status.appendChild(pill(boolLabel(enabled), enabled ? "allow" : "drop"));
        tr.appendChild(status);
        tr.appendChild(cell(pick(rule, ["comment"]) || "--"));
        tr.appendChild(groupAssignmentCell("rules", id, currentAssignments.get(String(id)), "global", currentGroups, groupsAvailable));
        const actions = document.createElement("td");
        const actionWrap = document.createElement("div");
        actionWrap.className = "table-actions";
        actionWrap.appendChild(actionButton("Edit", "edit", id, "secondary"));
        actionWrap.appendChild(actionButton(enabled ? "Disable" : "Enable", "toggle", id, "secondary"));
        actionWrap.appendChild(actionButton("Delete", "delete", id, "danger"));
        actions.appendChild(actionWrap);
        tr.appendChild(actions);
        target.body.appendChild(tr);
      }
    }

    async function refreshPage() {
      const [rules, groups] = await Promise.all([
        fetchOptionalJSON("/api/filter/rules"),
        fetchOptionalJSON("/api/filter/groups")
      ]);
      currentGroups = groups.ok ? normalizeGroups(groups.data) : [];
      groupsAvailable = groups.ok;
      const ruleItems = rules.ok ? normalizeRules(rules.data) : [];
      currentAssignments = rules.ok ? await loadGroupAssignments("rules", ruleItems) : new Map();
      renderRules(rules);
      setUpdatedStatus("Rules");
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
        const path = "/api/filter/rules/" + encodeURIComponent(ownerID) + "/groups";
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

    function payloadFromForm() {
      const pattern = target.pattern.value.trim();
      if (!pattern) {
        throw new Error("pattern is required");
      }
      return {
        pattern: pattern,
        kind: target.kind.value,
        match_type: target.matchType.value,
        enabled: target.enabled.checked,
        comment: target.comment.value.trim()
      };
    }

    function editRule(rule) {
      target.id.value = pick(rule, ["id"]) || "";
      target.pattern.value = pick(rule, ["pattern"]) || "";
      target.kind.value = pick(rule, ["kind"]) || "deny";
      target.matchType.value = pick(rule, ["match_type", "matchType"]) || "exact";
      target.comment.value = pick(rule, ["comment"]) || "";
      target.enabled.checked = Boolean(pick(rule, ["enabled"]));
      target.save.textContent = "Save rule";
      target.cancel.classList.remove("hidden");
      setUpdated("Editing rule " + displayValue(pick(rule, ["pattern"])) + ".");
      target.pattern.focus();
    }

    async function saveRule(event) {
      event.preventDefault();
      if (!rulesAvailable) {
        setUpdated("Rules API unavailable.");
        return;
      }
      let payload;
      try {
        payload = payloadFromForm();
      } catch (err) {
        setUpdated("Rule validation failed: " + err.message);
        return;
      }
      const id = target.id.value;
      target.save.disabled = true;
      try {
        await fetchJSON(id ? "/api/filter/rules/" + encodeURIComponent(id) : "/api/filter/rules", {
          method: id ? "PUT" : "POST",
          headers: {"content-type": "application/json"},
          body: JSON.stringify(payload)
        });
        resetForm();
        await refresh();
        setUpdated(id ? "Rule saved." : "Rule added.");
      } catch (err) {
        setUpdated("Rule save failed: " + err.message);
        target.save.disabled = false;
      }
    }

    async function handleAction(event) {
      const button = event.target.closest("button[data-action]");
      if (!button) {
        return;
      }
      if (await handleGroupAssignmentAction(button)) {
        return;
      }
      const rule = ruleByID(button.dataset.id);
      if (!rule) {
        return;
      }
      const id = pick(rule, ["id"]);
      if (button.dataset.action === "edit") {
        editRule(rule);
        return;
      }

      button.disabled = true;
      try {
        if (button.dataset.action === "toggle") {
          await fetchJSON("/api/filter/rules/" + encodeURIComponent(id), {
            method: "PUT",
            headers: {"content-type": "application/json"},
            body: JSON.stringify(payloadFromRecord(rule, !Boolean(pick(rule, ["enabled"]))))
          });
        } else if (button.dataset.action === "delete") {
          if (!window.confirm("Delete this rule?")) {
            button.disabled = false;
            return;
          }
          await fetchJSON("/api/filter/rules/" + encodeURIComponent(id), {method: "DELETE"});
          if (String(target.id.value) === String(id)) {
            resetForm();
          }
        }
        await refresh();
        setUpdated("Rule updated.");
      } catch (err) {
        setUpdated("Rule update failed: " + err.message);
        button.disabled = false;
      }
    }

    on(target.form, "submit", saveRule);
    on(target.cancel, "click", resetForm);
    on(target.body, "click", handleAction);

    return {refresh: refreshPage};
  }
});
