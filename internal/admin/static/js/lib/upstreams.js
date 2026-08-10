import {boolLabel, displayValue, firstDefined, listFrom, pick} from "./format.js";
import {cloneTemplate, emptyRow, setPillElement, setTemplateText, templateField} from "./elements.js";

export function upstreamEnabledValue(value) {
  if (value === undefined || value === null || value === "") {
    return true;
  }
  if (typeof value === "boolean") {
    return value;
  }
  const normalized = String(value).toLowerCase();
  return normalized !== "disabled" && normalized !== "false" && normalized !== "off";
}

export function normalizeUpstreams(value) {
  return listFrom(value).map(upstream => {
    if (upstream && typeof upstream === "object") {
      const enabled = firstDefined(upstream, ["enabled", "active", "status"]);
      return {
        name: displayValue(pick(upstream, ["name"])).replace(/^--$/, ""),
        address: displayValue(pick(upstream, ["address", "addr", "url", "server", "resolver"])).replace(/^--$/, ""),
        protocol: String(pick(upstream, ["protocol", "type", "scheme"]) || "udp").toLowerCase(),
        tls_server_name: displayValue(pick(upstream, ["tls_server_name", "tlsServerName"])).replace(/^--$/, ""),
        enabled: upstreamEnabledValue(enabled)
      };
    }
    return {
      name: "",
      address: displayValue(upstream).replace(/^--$/, ""),
      protocol: "udp",
      tls_server_name: "",
      enabled: true
    };
  });
}

export function renderUpstreamRows(upstreams, countField, body, editable) {
  const normalized = normalizeUpstreams(upstreams);
  body.textContent = "";
  countField.textContent = normalized.length + " configured";
  if (!normalized.length) {
    body.appendChild(emptyRow(editable ? 6 : 3, "No upstream resolvers reported."));
    return normalized;
  }
  normalized.forEach((upstream, index) => {
    const tr = cloneTemplate(editable ? "upstreamSettingsRow" : "upstreamDashboardRow");
    if (editable) {
      setTemplateText(tr, "name", upstream.name);
    }
    setTemplateText(tr, "resolver", upstream.address || upstream.name);
    setTemplateText(tr, "protocol", upstream.protocol || "udp");
    setPillElement(templateField(tr, "status"), boolLabel(upstream.enabled), upstream.enabled ? "allow" : "drop");
    if (editable) {
      setTemplateText(tr, "tls-server-name", upstream.tls_server_name || "--");
      Array.from(tr.querySelectorAll("button[data-action]")).forEach(button => {
        button.dataset.id = String(index);
        if (button.dataset.action === "toggle-upstream") {
          button.textContent = upstream.enabled ? "Disable" : "Enable";
        }
      });
    }
    body.appendChild(tr);
  });
  return normalized;
}
