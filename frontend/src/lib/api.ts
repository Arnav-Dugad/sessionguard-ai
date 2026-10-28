// Thin fetch wrapper. Cookies are same-origin via the Vite proxy; the CSRF token is read from
// the sg_csrf cookie and echoed on unsafe requests (double-submit), exactly as the backend expects.

export class ApiError extends Error {
  code: string;
  status: number;
  fields?: { field: string; message: string }[];
  extra: Record<string, unknown>;
  constructor(status: number, body: any) {
    const err = body?.error ?? {};
    super(err.message || `Request failed (${status})`);
    this.code = err.code || "error";
    this.status = status;
    this.fields = err.fields;
    this.extra = err;
  }
}

function csrfToken(): string | null {
  const m = document.cookie.match(/(?:^|;\s*)sg_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : null;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  const opts: RequestInit = { method, credentials: "same-origin", headers };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  if (method !== "GET" && method !== "HEAD") {
    const t = csrfToken();
    if (t) headers["X-CSRF-Token"] = t;
  }
  const res = await fetch(`/api${path}`, opts);
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) throw new ApiError(res.status, data);
  return data as T;
}

export const api = {
  get: <T>(p: string) => request<T>("GET", p),
  post: <T>(p: string, body?: unknown) => request<T>("POST", p, body),
  put: <T>(p: string, body?: unknown) => request<T>("PUT", p, body),
  del: <T>(p: string, body?: unknown) => request<T>("DELETE", p, body),
};
