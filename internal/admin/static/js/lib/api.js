let unauthorizedHandler = null;

export function configureAPI(options) {
  unauthorizedHandler = options?.onUnauthorized || null;
}

export async function fetchJSON(path, options) {
  const res = await fetch(path, options || {});
  if (res.status === 401) {
    if (unauthorizedHandler) {
      unauthorizedHandler();
    }
    throw new Error("authentication_required");
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || "request failed");
  }
  if (res.status === 204) {
    return null;
  }
  return res.json();
}

export async function fetchOptionalJSON(path, options) {
  try {
    return {ok: true, data: await fetchJSON(path, options)};
  } catch (err) {
    if (err.message === "authentication_required") {
      throw err;
    }
    return {ok: false, error: err.message};
  }
}
