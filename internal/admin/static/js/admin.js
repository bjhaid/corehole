import {configureAPI, fetchJSON} from "./lib/api.js";
import {on, required} from "./lib/dom.js";

export function initAdminPage(options) {
  const pageLabel = options?.label || "Console";
  const updated = required("#updated");
  const logoutButton = required("#logout");

  let refreshInFlight = false;
  const controller = options?.init ? options.init({
    isAuthenticated: () => true,
    refresh: refreshPage,
    setUpdated: text => {
      updated.textContent = text;
    },
    setUpdatedStatus,
    showLogin: () => redirectToLogin()
  }) : null;

  function setUpdatedStatus(label) {
    updated.textContent = label + " updated " + new Date().toLocaleTimeString();
  }

  function redirectToLogin() {
    window.location.assign("/admin/login");
  }

  async function refreshPage() {
    if (!controller || !controller.refresh || refreshInFlight) {
      return;
    }
    refreshInFlight = true;
    try {
      await controller.refresh();
    } finally {
      refreshInFlight = false;
    }
  }

  configureAPI({onUnauthorized: redirectToLogin});

  on(logoutButton, "click", async () => {
    if (controller && controller.stop) {
      controller.stop();
    }
    try {
      await fetchJSON("/api/logout", {method: "POST"});
    } finally {
      redirectToLogin();
    }
  });

  document.addEventListener("visibilitychange", () => {
    if (!controller) {
      return;
    }
    if (document.visibilityState === "hidden") {
      if (controller.stop) {
        controller.stop();
      }
      return;
    }
    if (controller.start) {
      controller.start();
    }
    refreshPage().catch(err => {
      if (err.message === "authentication_required") {
        redirectToLogin();
        return;
      }
      updated.textContent = pageLabel + " refresh failed: " + err.message;
    });
  });

  if (controller && controller.start) {
    controller.start();
  }
  refreshPage().catch(err => {
    if (err.message === "authentication_required") {
      redirectToLogin();
      return;
    }
    updated.textContent = pageLabel + " refresh failed: " + err.message;
  });
}
