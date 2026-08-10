export function setFormDisabled(form, disabled) {
  form.querySelectorAll("input, select, button").forEach(element => {
    element.disabled = disabled;
  });
}
