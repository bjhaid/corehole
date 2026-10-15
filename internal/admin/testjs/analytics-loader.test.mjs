import assert from "node:assert/strict";
import test from "node:test";
import {loadAnalyticsSections} from "../static/js/lib/analytics-loader.js";

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return {promise, resolve};
}

test("settings render while the summary is still pending", async () => {
  const summary = deferred();
  const settings = deferred();
  const rendered = [];
  const loading = loadAnalyticsSections(() => summary.promise, () => settings.promise,
    value => rendered.push(["summary", value]), value => rendered.push(["settings", value]));
  settings.resolve({ok: true});
  await Promise.resolve();
  assert.deepEqual(rendered, [["settings", {ok: true}]]);
  summary.resolve({ok: true});
  await loading;
  assert.equal(rendered[1][0], "summary");
});

test("summary renders without waiting for slow or failed settings", async () => {
  const settings = deferred();
  const rendered = [];
  const loading = loadAnalyticsSections(() => Promise.resolve({ok: true}), () => settings.promise,
    value => rendered.push(["summary", value]), value => rendered.push(["settings", value]));
  await Promise.resolve();
  assert.deepEqual(rendered, [["summary", {ok: true}]]);
  settings.resolve({ok: false, error: "unavailable"});
  await loading;
  assert.deepEqual(rendered[1], ["settings", {ok: false, error: "unavailable"}]);
});
