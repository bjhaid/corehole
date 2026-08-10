export const dnsQtypeNames = Object.freeze({
  1: "A",
  2: "NS",
  5: "CNAME",
  6: "SOA",
  12: "PTR",
  15: "MX",
  16: "TXT",
  28: "AAAA",
  33: "SRV",
  65: "HTTPS"
});

export function getPath(obj, path) {
  if (!obj || !path) {
    return undefined;
  }
  const parts = path.split(".");
  let current = obj;
  for (const part of parts) {
    if (current && Object.prototype.hasOwnProperty.call(current, part)) {
      current = current[part];
    } else {
      return undefined;
    }
  }
  return current;
}

export function pick(obj, paths) {
  for (const path of paths) {
    const value = getPath(obj, path);
    if (value !== undefined && value !== null && value !== "") {
      return value;
    }
  }
  return undefined;
}

export function listFrom(value) {
  if (Array.isArray(value)) {
    return value;
  }
  if (value && typeof value === "object") {
    return Object.values(value);
  }
  if (value === undefined || value === null || value === "") {
    return [];
  }
  return [value];
}

export function displayValue(value) {
  if (Array.isArray(value)) {
    return value.length ? value.map(displayValue).join(", ") : "--";
  }
  if (value && typeof value === "object") {
    const preferred = pick(value, ["address", "addr", "url", "name", "value"]);
    return preferred === undefined ? JSON.stringify(value) : displayValue(preferred);
  }
  if (value === undefined || value === null || value === "") {
    return "--";
  }
  return String(value);
}

export function displayNumber(value) {
  if (Array.isArray(value)) {
    return String(value.length);
  }
  if (typeof value === "number") {
    return new Intl.NumberFormat().format(value);
  }
  if (typeof value === "string" && value.trim() !== "" && !Number.isNaN(Number(value))) {
    return new Intl.NumberFormat().format(Number(value));
  }
  return displayValue(value);
}

export function formatTime(value) {
  if (!value) {
    return "--";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return displayValue(value);
  }
  return date.toLocaleString();
}

export function boolLabel(value) {
  return value ? "enabled" : "disabled";
}

export function bundledConfigValue(data) {
  return pick(data, ["blocking_bundled", "blockingBundled", "blocking.bundled"]);
}

export function dnssecConfigValue(data) {
  return pick(data, ["dnssec", "dns.dnssec"]);
}

export function firstDefined(obj, paths) {
  for (const path of paths) {
    const value = getPath(obj, path);
    if (value !== undefined && value !== null) {
      return value;
    }
  }
  return undefined;
}
