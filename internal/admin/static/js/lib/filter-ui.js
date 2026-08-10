import {fetchOptionalJSON} from "./api.js";
import {actionButton, pill} from "./elements.js";
import {displayValue, listFrom, pick} from "./format.js";

export function normalizeFilterLists(data) {
  if (Array.isArray(data)) {
    return data;
  }
  return listFrom(pick(data, ["lists", "items", "results", "data"]));
}

export function normalizeRules(data) {
  if (Array.isArray(data)) {
    return data;
  }
  return listFrom(pick(data, ["rules", "items", "results", "data"]));
}

export function normalizeClients(data) {
  if (Array.isArray(data)) {
    return data;
  }
  return listFrom(pick(data, ["clients", "items", "results", "data"]));
}

export function normalizeClientSuggestions(data) {
  if (Array.isArray(data)) {
    return data;
  }
  return listFrom(pick(data, ["suggestions", "clients", "items", "results", "data"]));
}

export function normalizeGroups(data) {
  if (Array.isArray(data)) {
    return data;
  }
  return listFrom(pick(data, ["groups", "items", "results", "data"]));
}

export async function loadGroupAssignments(resource, items) {
  const assignments = await Promise.all(items.map(async item => {
    const id = pick(item, ["id"]);
    if (!id) {
      return [String(id), {ok: true, groups: []}];
    }
    const result = await fetchOptionalJSON("/api/filter/" + resource + "/" + encodeURIComponent(id) + "/groups");
    return [String(id), result.ok
      ? {ok: true, groups: normalizeGroups(result.data)}
      : {ok: false, error: result.error}];
  }));
  return new Map(assignments);
}

export function groupAssignmentCell(resource, ownerID, assignment, emptyText, groups, groupsAvailable) {
  const td = document.createElement("td");
  const wrap = document.createElement("div");
  wrap.className = "group-assignment";

  const assigned = assignment && assignment.ok ? assignment.groups : [];
  const assignedIDs = new Set(assigned.map(group => String(pick(group, ["id"]))));
  const pills = document.createElement("div");
  pills.className = "assignment-pills";
  if (assignment && !assignment.ok) {
    pills.appendChild(pill("unavailable", "drop"));
  } else if (!assigned.length) {
    pills.appendChild(pill(emptyText, ""));
  } else {
    for (const group of assigned) {
      const groupID = pick(group, ["id"]);
      pills.appendChild(pill(pick(group, ["name"]) || groupID, Boolean(pick(group, ["enabled"])) ? "allow" : "drop"));
      const remove = actionButton("Remove", "remove-group", ownerID, "secondary");
      remove.dataset.resource = resource;
      remove.dataset.groupId = String(groupID);
      pills.appendChild(remove);
    }
  }
  wrap.appendChild(pills);

  const availableGroups = groups.filter(group => !assignedIDs.has(String(pick(group, ["id"]))));
  const add = document.createElement("div");
  add.className = "assignment-add";
  const select = document.createElement("select");
  select.dataset.role = "group-select";
  select.disabled = !groupsAvailable || !availableGroups.length || Boolean(assignment && !assignment.ok);
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = availableGroups.length ? "Select group" : "No groups";
  select.appendChild(placeholder);
  for (const group of availableGroups) {
    const option = document.createElement("option");
    option.value = String(pick(group, ["id"]));
    option.textContent = displayValue(pick(group, ["name"]));
    select.appendChild(option);
  }
  const button = actionButton("Assign", "assign-group", ownerID, "secondary");
  button.dataset.resource = resource;
  button.disabled = select.disabled;
  add.appendChild(select);
  add.appendChild(button);
  wrap.appendChild(add);

  td.appendChild(wrap);
  return td;
}
