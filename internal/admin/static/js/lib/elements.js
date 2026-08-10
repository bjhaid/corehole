import {displayValue} from "./format.js";

let templates = {};

export function configureTemplates(nextTemplates) {
  templates = nextTemplates || {};
}

export function setText(element, value) {
  element.textContent = displayValue(value);
}

export function cloneTemplate(name) {
  const template = templates[name];
  if (!template || !template.content.firstElementChild) {
    throw new Error("missing template: " + name);
  }
  return template.content.firstElementChild.cloneNode(true);
}

export function templateField(root, name) {
  return root.querySelector('[data-field="' + name + '"]');
}

export function setTemplateText(root, name, value) {
  const element = templateField(root, name);
  if (element) {
    element.textContent = displayValue(value);
  }
  return element;
}

export function setPillElement(element, text, kind) {
  element.className = "pill" + (kind ? " " + kind : "");
  element.textContent = displayValue(text);
}

export function emptyRow(colspan, text) {
  const tr = cloneTemplate("emptyRow");
  const td = templateField(tr, "message");
  td.colSpan = colspan;
  td.textContent = text;
  return tr;
}

export function cell(text) {
  const td = document.createElement("td");
  td.textContent = displayValue(text);
  return td;
}

export function actionButton(text, action, id, className) {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = text;
  button.dataset.action = action;
  button.dataset.id = String(id);
  if (className) {
    button.className = className;
  }
  return button;
}

export function pill(text, kind) {
  const span = document.createElement("span");
  setPillElement(span, text, kind);
  return span;
}

export function classifyAction(action) {
  const normalized = String(action || "").toLowerCase();
  if (normalized.includes("block") || normalized.includes("deny")) {
    return "block";
  }
  if (normalized.includes("drop")) {
    return "drop";
  }
  if (normalized.includes("allow") || normalized.includes("pass") || normalized.includes("resolve")) {
    return "allow";
  }
  return "";
}
