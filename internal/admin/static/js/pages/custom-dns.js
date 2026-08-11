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
    body: required("#localdns-body"),
    rewriteStatus: required("#rewrite-status"),
    rewriteForm: required("#rewrite-form"),
    rewriteIndex: required("#rewrite-index"),
    rewriteField: required("#rewrite-field"),
    rewriteMode: required("#rewrite-mode"),
    rewriteMatch: required("#rewrite-match"),
    rewriteFromLabel: required("#rewrite-from-label"),
    rewriteFrom: required("#rewrite-from"),
    rewriteToLabel: required("#rewrite-to-label"),
    rewriteTo: required("#rewrite-to"),
    rewriteRCodeFrom: required("#rewrite-rcode-from"),
    rewriteRCodeTo: required("#rewrite-rcode-to"),
    rewriteAnswerMode: required("#rewrite-answer-mode"),
    rewriteAnswerFrom: required("#rewrite-answer-from"),
    rewriteAnswerTo: required("#rewrite-answer-to"),
    rewriteEnabled: required("#rewrite-enabled"),
    rewriteComment: required("#rewrite-comment"),
    rewriteSave: required("#rewrite-save"),
    rewriteCancel: required("#rewrite-cancel"),
    rewriteMessage: required("#rewrite-message"),
    rewriteBody: required("#rewrite-body"),
    rewriteMatchField: required("[data-rewrite-match-field]"),
    rewriteToField: required("[data-rewrite-to-field]")
  };
}

function normalizeLocalDNSRecords(data) {
  if (Array.isArray(data)) {
    return data;
  }
  return listFrom(pick(data, ["records", "items", "results", "data"]));
}

function normalizeRewriteRules(data) {
  return listFrom(pick(data, ["rewrites", "dns.rewrites"]));
}

function rewriteText(rule) {
  const field = String(pick(rule, ["field"]) || "name").toLowerCase();
  if (field === "rcode") {
    return (pick(rule, ["rcode_from"]) || "--") + " -> " + (pick(rule, ["rcode_to"]) || "--");
  }
  return pick(rule, ["to"]) || "--";
}

function answerText(rule) {
  const mode = String(pick(rule, ["answer_mode"]) || "none").toLowerCase();
  if (mode === "auto") {
    return "auto";
  }
  if (mode === "name" || mode === "value") {
    return mode + ": " + (pick(rule, ["answer_from"]) || "--") + " -> " + (pick(rule, ["answer_to"]) || "--");
  }
  return "--";
}

initAdminPage({
  label: "Custom DNS",
  init({refresh, setUpdatedStatus}) {
    const target = fields();
    let currentRecords = [];
    let currentRewrites = [];
    let configAvailable = false;
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

    function setRewriteMessage(text, isError) {
      target.rewriteMessage.textContent = text || "";
      target.rewriteMessage.classList.toggle("error", Boolean(isError));
    }

    function resetRewriteForm() {
      target.rewriteForm.reset();
      target.rewriteIndex.value = "";
      target.rewriteField.value = "name";
      target.rewriteMode.value = "stop";
      target.rewriteMatch.value = "exact";
      target.rewriteAnswerMode.value = "none";
      target.rewriteEnabled.checked = true;
      target.rewriteSave.textContent = "Add rewrite";
      target.rewriteCancel.classList.add("hidden");
      syncRewriteForm();
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
        target.body.appendChild(emptyRow(7, "Custom DNS records unavailable."));
        setFormDisabled(target.form, true);
        return;
      }

      currentRecords = normalizeLocalDNSRecords(result.data);
      recordsAvailable = true;
      target.status.textContent = currentRecords.length + " records";
      setFormDisabled(target.form, false);
      target.cancel.disabled = false;

      if (!currentRecords.length) {
        target.body.appendChild(emptyRow(7, "No custom DNS records configured."));
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

    function renderRewrites(result) {
      target.rewriteBody.textContent = "";
      if (!result.ok) {
        configAvailable = false;
        currentRewrites = [];
        target.rewriteStatus.textContent = "Unavailable: " + displayValue(result.error);
        target.rewriteBody.appendChild(emptyRow(8, "Rewrite rules unavailable."));
        setFormDisabled(target.rewriteForm, true);
        return;
      }

      configAvailable = true;
      currentRewrites = normalizeRewriteRules(result.data);
      target.rewriteStatus.textContent = currentRewrites.length + " rules";
      setFormDisabled(target.rewriteForm, false);
      target.rewriteCancel.disabled = false;
      syncRewriteForm();

      if (!currentRewrites.length) {
        target.rewriteBody.appendChild(emptyRow(8, "No rewrite rules configured."));
        return;
      }

      currentRewrites.forEach((rule, index) => {
        const enabled = Boolean(pick(rule, ["enabled"]));
        const field = String(pick(rule, ["field"]) || "name").toLowerCase();
        const tr = document.createElement("tr");
        tr.appendChild(cell(field));
        tr.appendChild(cell(field === "type" ? "--" : pick(rule, ["match"]) || "exact"));
        tr.appendChild(cell(pick(rule, ["from"])));
        tr.appendChild(cell(rewriteText(rule)));
        tr.appendChild(cell(answerText(rule)));
        const status = document.createElement("td");
        status.className = "status-cell";
        status.appendChild(pill(boolLabel(enabled), enabled ? "allow" : "drop"));
        tr.appendChild(status);
        tr.appendChild(cell(pick(rule, ["comment"]) || "--"));
        const actions = document.createElement("td");
        const actionWrap = document.createElement("div");
        actionWrap.className = "table-actions";
        actionWrap.appendChild(actionButton("Edit", "rewrite-edit", index, "secondary"));
        actionWrap.appendChild(actionButton(enabled ? "Disable" : "Enable", "rewrite-toggle", index, "secondary"));
        actionWrap.appendChild(actionButton("Delete", "rewrite-delete", index, "danger"));
        actions.appendChild(actionWrap);
        tr.appendChild(actions);
        target.rewriteBody.appendChild(tr);
      });
    }

    async function refreshPage() {
      const [records, config] = await Promise.all([
        fetchOptionalJSON("/api/custom-dns/records"),
        fetchOptionalJSON("/api/config")
      ]);
      renderRecords(records);
      renderRewrites(config);
      setUpdatedStatus("Custom DNS");
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

    function syncRewriteForm() {
      const field = target.rewriteField.value;
      const answerMode = target.rewriteAnswerMode.value;
      const isType = field === "type";
      const isRCode = field === "rcode";
      const isName = field === "name";
      target.rewriteMatchField.classList.toggle("hidden", isType);
      target.rewriteToField.classList.toggle("hidden", isRCode);
      document.querySelectorAll("[data-rewrite-rcode-field]").forEach(el => el.classList.toggle("hidden", !isRCode));
      document.querySelectorAll("[data-rewrite-answer-field]").forEach(el => el.classList.toggle("hidden", !isName));
      document.querySelectorAll("[data-rewrite-answer-detail]").forEach(el => el.classList.toggle("hidden", !isName || (answerMode !== "name" && answerMode !== "value")));
      target.rewriteFromLabel.textContent = isType ? "Type from" : "Match value";
      target.rewriteToLabel.textContent = field === "ttl" ? "TTL value or range" : "To";
      target.rewriteTo.required = !isRCode;
      target.rewriteAnswerFrom.required = isName && (answerMode === "name" || answerMode === "value");
      target.rewriteAnswerTo.required = target.rewriteAnswerFrom.required;
    }

    function rewritePayloadFromForm() {
      const field = target.rewriteField.value;
      const answerMode = target.rewriteAnswerMode.value;
      const payload = {
        enabled: target.rewriteEnabled.checked,
        mode: target.rewriteMode.value,
        field: field,
        match: field === "type" ? "" : target.rewriteMatch.value,
        from: target.rewriteFrom.value.trim(),
        to: field === "rcode" ? "" : target.rewriteTo.value.trim(),
        rcode_from: field === "rcode" ? target.rewriteRCodeFrom.value : "",
        rcode_to: field === "rcode" ? target.rewriteRCodeTo.value : "",
        answer_mode: field === "name" ? answerMode : "",
        answer_from: field === "name" && (answerMode === "name" || answerMode === "value") ? target.rewriteAnswerFrom.value.trim() : "",
        answer_to: field === "name" && (answerMode === "name" || answerMode === "value") ? target.rewriteAnswerTo.value.trim() : "",
        comment: target.rewriteComment.value.trim()
      };
      if (!payload.from) {
        throw new Error("rewrite match value is required");
      }
      if (field !== "rcode" && !payload.to) {
        throw new Error("rewrite target is required");
      }
      if ((payload.answer_mode === "name" || payload.answer_mode === "value") && (!payload.answer_from || !payload.answer_to)) {
        throw new Error("answer rewrite from and to are required");
      }
      return payload;
    }

    function editRewrite(rule, index) {
      target.rewriteIndex.value = String(index);
      target.rewriteField.value = pick(rule, ["field"]) || "name";
      target.rewriteMode.value = pick(rule, ["mode"]) || "stop";
      target.rewriteMatch.value = pick(rule, ["match"]) || "exact";
      target.rewriteFrom.value = pick(rule, ["from"]) || "";
      target.rewriteTo.value = pick(rule, ["to"]) || "";
      target.rewriteRCodeFrom.value = pick(rule, ["rcode_from"]) || "NOERROR";
      target.rewriteRCodeTo.value = pick(rule, ["rcode_to"]) || "NXDOMAIN";
      target.rewriteAnswerMode.value = pick(rule, ["answer_mode"]) || "none";
      target.rewriteAnswerFrom.value = pick(rule, ["answer_from"]) || "";
      target.rewriteAnswerTo.value = pick(rule, ["answer_to"]) || "";
      target.rewriteEnabled.checked = Boolean(pick(rule, ["enabled"]));
      target.rewriteComment.value = pick(rule, ["comment"]) || "";
      target.rewriteSave.textContent = "Save rewrite";
      target.rewriteCancel.classList.remove("hidden");
      syncRewriteForm();
      setRewriteMessage("");
      target.rewriteFrom.focus();
    }

    async function saveRewriteRules(rules, message) {
      const result = await fetchJSON("/api/config", {
        method: "PUT",
        headers: {"content-type": "application/json"},
        body: JSON.stringify({dns: {rewrites: rules}})
      });
      renderRewrites({ok: true, data: result.config || {}});
      setRewriteMessage(message, false);
      setUpdatedStatus(result.restart_required ? "Custom DNS saved; restart required" : "Custom DNS updated");
    }

    async function saveRewrite(event) {
      event.preventDefault();
      if (!configAvailable) {
        setRewriteMessage("Config API unavailable.", true);
        return;
      }
      let payload;
      try {
        payload = rewritePayloadFromForm();
      } catch (err) {
        setRewriteMessage(err.message, true);
        return;
      }
      const index = target.rewriteIndex.value;
      const next = currentRewrites.slice();
      if (index === "") {
        next.push(payload);
      } else {
        next[Number(index)] = payload;
      }
      target.rewriteSave.disabled = true;
      try {
        await saveRewriteRules(next, index === "" ? "Rewrite added." : "Rewrite saved.");
        resetRewriteForm();
      } catch (err) {
        setRewriteMessage("Rewrite save failed: " + err.message, true);
        target.rewriteSave.disabled = false;
      }
    }

    async function saveRecord(event) {
      event.preventDefault();
      if (!recordsAvailable) {
        setMessage("Custom DNS records API unavailable.", true);
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
        await fetchJSON(id ? "/api/custom-dns/records/" + encodeURIComponent(id) : "/api/custom-dns/records", {
          method: id ? "PUT" : "POST",
          headers: {"content-type": "application/json"},
          body: JSON.stringify(payload)
        });
        resetForm();
        await refresh();
        setMessage(id ? "Record saved." : "Record added.", false);
      } catch (err) {
        setMessage("Custom DNS record save failed: " + err.message, true);
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
          await fetchJSON("/api/custom-dns/records/" + encodeURIComponent(id), {
            method: "PUT",
            headers: {"content-type": "application/json"},
            body: JSON.stringify(payloadFromRecord(record, enabled))
          });
          await refresh();
          setMessage("Record " + boolLabel(enabled) + ".", false);
        } else if (button.dataset.action === "delete") {
          if (!window.confirm("Delete this custom DNS record?")) {
            button.disabled = false;
            return;
          }
          await fetchJSON("/api/custom-dns/records/" + encodeURIComponent(id), {method: "DELETE"});
          if (String(target.id.value) === String(id)) {
            resetForm();
          }
          await refresh();
          setMessage("Record deleted.", false);
        }
      } catch (err) {
        setMessage("Custom DNS record update failed: " + err.message, true);
        button.disabled = false;
      }
    }

    async function handleRewriteAction(event) {
      const button = event.target.closest("button[data-action]");
      if (!button) {
        return;
      }
      const index = Number(button.dataset.id);
      const rule = currentRewrites[index];
      if (!rule) {
        return;
      }
      if (button.dataset.action === "rewrite-edit") {
        editRewrite(rule, index);
        return;
      }

      button.disabled = true;
      try {
        const next = currentRewrites.slice();
        if (button.dataset.action === "rewrite-toggle") {
          const enabled = !Boolean(pick(rule, ["enabled"]));
          next[index] = {...rule, enabled};
          await saveRewriteRules(next, "Rewrite " + boolLabel(enabled) + ".");
        } else if (button.dataset.action === "rewrite-delete") {
          if (!window.confirm("Delete this rewrite rule?")) {
            button.disabled = false;
            return;
          }
          next.splice(index, 1);
          await saveRewriteRules(next, "Rewrite deleted.");
          if (String(target.rewriteIndex.value) === String(index)) {
            resetRewriteForm();
          }
        }
      } catch (err) {
        setRewriteMessage("Rewrite update failed: " + err.message, true);
        button.disabled = false;
      }
    }

    on(target.form, "submit", saveRecord);
    on(target.cancel, "click", () => {
      resetForm();
      setMessage("");
    });
    on(target.body, "click", handleAction);
    on(target.rewriteForm, "submit", saveRewrite);
    on(target.rewriteCancel, "click", () => {
      resetRewriteForm();
      setRewriteMessage("");
    });
    on(target.rewriteField, "change", syncRewriteForm);
    on(target.rewriteAnswerMode, "change", syncRewriteForm);
    on(target.rewriteBody, "click", handleRewriteAction);
    resetRewriteForm();

    return {refresh: refreshPage};
  }
});
