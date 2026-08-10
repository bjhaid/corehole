import {configureAPI, fetchJSON} from "./lib/api.js";
import {on, required} from "./lib/dom.js";

const authModeSetup = "setup";
const authModeLogin = "login";

export function initAdminPage(options) {
  const pageLabel = options?.label || "Console";
  const authView = required("#auth-view");
  const appView = required("#app-view");
  const setupPanel = required("#setup-panel");
  const loginPanel = required("#login-panel");
  const setupForm = required("#setup");
  const loginForm = required("#login");
  const summary = required("#summary");
  const message = required("#message");
  const sessionState = required("#session-state");
  const logoutButton = required("#logout");
  const updated = required("#updated");

  let authenticated = false;
  let refreshInFlight = false;
  let controller = null;

  function setMessage(text, isError) {
    message.textContent = text || "";
    message.classList.toggle("error", Boolean(isError));
  }

  function setUpdatedStatus(label) {
    updated.textContent = label + " updated " + new Date().toLocaleTimeString();
  }

  function showAuth(mode) {
    const showingSetup = mode === authModeSetup;
    const showingLogin = mode === authModeLogin;
    authenticated = false;
    if (controller && controller.stop) {
      controller.stop();
    }
    authView.classList.remove("hidden");
    appView.classList.add("hidden");
    logoutButton.classList.add("hidden");
    setupPanel.classList.toggle("hidden", !showingSetup);
    loginPanel.classList.toggle("hidden", !showingLogin);
    sessionState.textContent = showingSetup ? "Setup required" : "Logged out";
    summary.textContent = showingSetup ? "Create the first admin password." : "Log in to manage Corehole.";
  }

  function showApp() {
    authenticated = true;
    authView.classList.add("hidden");
    appView.classList.remove("hidden");
    logoutButton.classList.remove("hidden");
    sessionState.textContent = "Authenticated";
    setMessage("");
    if (controller && controller.start) {
      controller.start();
    }
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

  async function status() {
    const body = await fetchJSON("/api/status");
    const setupRequired = body?.setup_required === true;
    const loggedIn = body?.authenticated === true;
    if (setupRequired) {
      showAuth(authModeSetup);
      return false;
    }
    if (!loggedIn) {
      showAuth(authModeLogin);
      return false;
    }
    showApp();
    await refreshPage();
    return true;
  }

  async function postPassword(path, password) {
    await fetchJSON(path, {
      method: "POST",
      headers: {"content-type": "application/json"},
      body: JSON.stringify({password: password})
    });
  }

  configureAPI({onUnauthorized: () => showAuth(authModeLogin)});

  controller = options?.init ? options.init({
    isAuthenticated: () => authenticated,
    refresh: refreshPage,
    setUpdated: text => {
      updated.textContent = text;
    },
    setUpdatedStatus,
    showLogin: () => showAuth(authModeLogin)
  }) : null;

  showAuth(authModeLogin);

  on(setupForm, "submit", async event => {
    event.preventDefault();
    setMessage("");
    try {
      await postPassword("/api/setup", new FormData(setupForm).get("password"));
      await status();
    } catch (err) {
      setMessage(err.message, true);
    }
  });

  on(loginForm, "submit", async event => {
    event.preventDefault();
    setMessage("");
    try {
      await postPassword("/api/login", new FormData(loginForm).get("password"));
      await status();
    } catch (err) {
      setMessage(err.message, true);
    }
  });

  on(logoutButton, "click", async () => {
    if (controller && controller.stop) {
      controller.stop();
    }
    try {
      await fetchJSON("/api/logout", {method: "POST"});
    } finally {
      await status();
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
    if (authenticated) {
      if (controller.start) {
        controller.start();
      }
      refreshPage().catch(err => {
        if (err.message === "authentication_required") {
          showAuth(authModeLogin);
          return;
        }
        updated.textContent = pageLabel + " refresh failed: " + err.message;
      });
    }
  });

  status().catch(err => {
    showAuth(authModeLogin);
    summary.textContent = "Admin console unavailable.";
    setMessage(err.message, true);
  });
}
