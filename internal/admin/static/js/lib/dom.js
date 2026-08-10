export function qs(selector, root) {
  return (root || document).querySelector(selector);
}

export function qsa(selector, root) {
  return Array.from((root || document).querySelectorAll(selector));
}

export function optional(selector, root) {
  return qs(selector, root);
}

export function required(selector, root) {
  const element = qs(selector, root);
  if (!element) {
    throw new Error("missing element: " + selector);
  }
  return element;
}

export function on(element, eventName, handler) {
  if (element) {
    element.addEventListener(eventName, handler);
  }
}
