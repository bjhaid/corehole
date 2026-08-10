import {initAdminPage} from "../admin.js";
import {fetchJSON, fetchOptionalJSON} from "../lib/api.js";
import {on, required} from "../lib/dom.js";
import {actionButton, cell, configureTemplates, emptyRow, pill} from "../lib/elements.js";
import {boolLabel, displayValue, listFrom, pick} from "../lib/format.js";
import {setFormDisabled} from "../lib/forms.js";

function fields() {
  return {
    status: required("#localdns-status"),
    form: required("#localdns-form"),
    id: required("#localdns-id"),
    name: required("#localdns-name"),
    type: required("#localdns-type"),
    value: required("#localdns-value"),
    ttl: required("#localdns-ttl"),
    enabled: required("#localdns-enabled"),
    comment: required("#localdns-comment"),
    save: required("#localdns-save"),
    cancel: required("#localdns-cancel"),
    message: required("#localdns-message"),
    body: required("#localdns-body")
  };
}

function normalizeLocalDNSRecords(data) {
  if (Array.isArray(data)) {
    return data;
  }
  return listFrom(pick(data, ["records", "items", "results", "data"]));
}

initAdminPage({
  label: "Local DNS",
  init({refresh, setUpdatedStatus}) {
    const target = fields();
    let currentRecords = [];
    let recordsAvailable = false;

    configureTemplates({emptyRow: required("#template-empty-row")});

    function setMessage(text, isError) {
      target.message.textContent = text || "";
      target.message.classList.toggle("error", Boolean(isError));
    }

    function resetForm() {
      target.form.reset();
      target.id.value = "";
      target.type.value = "A";
      target.ttl.value = "300";
      target.enabled.checked = true;
      target.save.textContent = "Add record";
      target.cancel.classList.add("hidden");
    }

    function recordByID(id) {
      return currentRecords.find(record => String(pick(record, ["id"])) === String(id));
    }

    function payloadFromRecord(record, enabled) {
      return {
        name: pick(record, ["name"]) || "",
        type: pick(record, ["type"]) || "A",
        value: pick(record, ["value"]) || "",
        ttl: Number(pick(record, ["ttl"]) || 0),
        enabled: enabled,
        comment: pick(record, ["comment"]) || ""
      };
    }

    function renderRecords(result) {
      target.body.textContent = "";
      if (!result.ok) {
        currentRecords = [];
        recordsAvailable = false;
        target.status.textContent = "Unavailable: " + displayValue(result.error);
        target.body.appendChild(emptyRow(7, "Local DNS records unavailable."));
        setFormDisabled(target.form, true);
        return;
      }

      currentRecords = normalizeLocalDNSRecords(result.data);
      recordsAvailable = true;
      target.status.textContent = currentRecords.length + " records";
      setFormDisabled(target.form, false);
      target.cancel.disabled = false;

      if (!currentRecords.length) {
        target.body.appendChild(emptyRow(7, "No local DNS records configured."));
        return;
      }

      for (const record of currentRecords) {
        const id = pick(record, ["id"]);
        const enabled = Boolean(pick(record, ["enabled"]));
        const tr = document.createElement("tr");
        tr.appendChild(cell(pick(record, ["name"])));
        tr.appendChild(cell(pick(record, ["type"])));
        tr.appendChild(cell(pick(record, ["value"])));
        tr.appendChild(cell(pick(record, ["ttl"])));
        const status = document.createElement("td");
        status.className = "status-cell";
        status.appendChild(pill(boolLabel(enabled), enabled ? "allow" : "drop"));
        tr.appendChild(status);
        tr.appendChild(cell(pick(record, ["comment"]) || "--"));
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
      renderRecords(await fetchOptionalJSON("/api/localdns/records"));
      setUpdatedStatus("Local DNS");
    }

    function payloadFromForm() {
      const name = target.name.value.trim();
      const value = target.value.value.trim();
      const ttlText = target.ttl.value.trim();
      const ttl = ttlText === "" ? 0 : Number(ttlText);
      if (!name) {
        throw new Error("name is required");
      }
      if (!value) {
        throw new Error("value is required");
      }
      if (!Number.isInteger(ttl) || ttl < 0 || ttl > 604800) {
        throw new Error("ttl must be between 0 and 604800");
      }
      return {
        name: name,
        type: target.type.value,
        value: value,
        ttl: ttl,
        enabled: target.enabled.checked,
        comment: target.comment.value.trim()
      };
    }

    function editRecord(record) {
      target.id.value = pick(record, ["id"]) || "";
      target.name.value = pick(record, ["name"]) || "";
      target.type.value = pick(record, ["type"]) || "A";
      target.value.value = pick(record, ["value"]) || "";
      target.ttl.value = pick(record, ["ttl"]) || "300";
      target.enabled.checked = Boolean(pick(record, ["enabled"]));
      target.comment.value = pick(record, ["comment"]) || "";
      target.save.textContent = "Save record";
      target.cancel.classList.remove("hidden");
      setMessage("");
      target.name.focus();
    }

    async function saveRecord(event) {
      event.preventDefault();
      if (!recordsAvailable) {
        setMessage("Local DNS API unavailable.", true);
        return;
      }
      let payload;
      try {
        payload = payloadFromForm();
      } catch (err) {
        setMessage(err.message, true);
        return;
      }

      const id = target.id.value;
      target.save.disabled = true;
      try {
        await fetchJSON(id ? "/api/localdns/records/" + encodeURIComponent(id) : "/api/localdns/records", {
          method: id ? "PUT" : "POST",
          headers: {"content-type": "application/json"},
          body: JSON.stringify(payload)
        });
        resetForm();
        await refresh();
        setMessage(id ? "Record saved." : "Record added.", false);
      } catch (err) {
        setMessage("Local DNS save failed: " + err.message, true);
        target.save.disabled = false;
      }
    }

    async function handleAction(event) {
      const button = event.target.closest("button[data-action]");
      if (!button) {
        return;
      }
      const record = recordByID(button.dataset.id);
      if (!record) {
        return;
      }
      const id = pick(record, ["id"]);
      if (button.dataset.action === "edit") {
        editRecord(record);
        return;
      }

      button.disabled = true;
      try {
        if (button.dataset.action === "toggle") {
          const enabled = !Boolean(pick(record, ["enabled"]));
          await fetchJSON("/api/localdns/records/" + encodeURIComponent(id), {
            method: "PUT",
            headers: {"content-type": "application/json"},
            body: JSON.stringify(payloadFromRecord(record, enabled))
          });
          await refresh();
          setMessage("Record " + boolLabel(enabled) + ".", false);
        } else if (button.dataset.action === "delete") {
          if (!window.confirm("Delete this local DNS record?")) {
            button.disabled = false;
            return;
          }
          await fetchJSON("/api/localdns/records/" + encodeURIComponent(id), {method: "DELETE"});
          if (String(target.id.value) === String(id)) {
            resetForm();
          }
          await refresh();
          setMessage("Record deleted.", false);
        }
      } catch (err) {
        setMessage("Local DNS update failed: " + err.message, true);
        button.disabled = false;
      }
    }

    on(target.form, "submit", saveRecord);
    on(target.cancel, "click", () => {
      resetForm();
      setMessage("");
    });
    on(target.body, "click", handleAction);

    return {refresh: refreshPage};
  }
});
