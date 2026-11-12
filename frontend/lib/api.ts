export class ApiError extends Error {
  constructor(public status: number, message: string, public errors?: { field: string; message: string }[], public headers?: Headers) { super(message); }
}
const cookie = (n: string) => (typeof document === "undefined" ? "" : document.cookie.split("; ").find((c) => c.startsWith(n + "="))?.split("=")[1] ?? "");
let refreshing: Promise<boolean> | null = null;

async function refresh(): Promise<boolean> {
  refreshing ??= fetch("/api/auth/refresh", { method: "POST", credentials: "include", headers: { "X-CSRF-Token": cookie("lg_csrf") } })
    .then((r) => r.ok).catch(() => false).finally(() => { setTimeout(() => (refreshing = null), 0); });
  return refreshing;
}

export async function api<T = any>(path: string, opts: { method?: string; body?: unknown; form?: FormData; raw?: boolean; params?: Record<string, any> } = {}, retried = false): Promise<T> {
  const qs = opts.params ? "?" + new URLSearchParams(Object.entries(opts.params).filter(([, v]) => v !== undefined && v !== "" && v !== null).map(([k, v]) => [k, String(v)])).toString() : "";
  const method = opts.method ?? "GET";
  const headers: Record<string, string> = {};
  if (method !== "GET") headers["X-CSRF-Token"] = cookie("lg_csrf");
  let body: BodyInit | undefined;
  if (opts.form) body = opts.form;
  else if (opts.body !== undefined) { headers["Content-Type"] = "application/json"; body = JSON.stringify(opts.body); }
  const res = await fetch(`/api${path}${qs}`, { method, headers, body, credentials: "include" });
  if (res.status === 401 && !retried && !path.startsWith("/auth/login") && !path.startsWith("/auth/refresh") && (await refresh())) return api<T>(path, opts, true);
  if (opts.raw) { if (!res.ok) throw new ApiError(res.status, "Request failed"); return res as unknown as T; }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, typeof data.detail === "string" ? data.detail : "Request failed", data.errors, res.headers);
  return data as T;
}

export async function download(path: string, filename?: string) {
  const res = await api<Response>(path, { raw: true });
  const blob = await res.blob();
  const cd = res.headers.get("content-disposition")?.match(/filename="([^"]+)"/)?.[1];
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = filename ?? cd ?? "download"; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}
