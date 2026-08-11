import {fetchJSON} from "../lib/api.js";
import {on, required} from "../lib/dom.js";

const setupForm = document.querySelector("#setup");
const loginForm = document.querySelector("#login");
const message = required("#message");

function setMessage(text, isError) {
  message.textContent = text || "";
  message.classList.toggle("error", Boolean(isError));
}

async function postPassword(path, form) {
  const password = new FormData(form).get("password");
  await fetchJSON(path, {
    method: "POST",
    headers: {"content-type": "application/json"},
    body: JSON.stringify({password})
  });
  window.location.assign("/admin/dashboard");
}

if (setupForm) {
  on(setupForm, "submit", async event => {
    event.preventDefault();
    setMessage("");
    try {
      await postPassword("/api/setup", setupForm);
    } catch (err) {
      setMessage(err.message, true);
    }
  });
}

if (loginForm) {
  on(loginForm, "submit", async event => {
    event.preventDefault();
    setMessage("");
    try {
      await postPassword("/api/login", loginForm);
    } catch (err) {
      if (err.message === "setup_required") {
        window.location.assign("/admin/setup");
        return;
      }
      setMessage(err.message, true);
    }
  });
}
