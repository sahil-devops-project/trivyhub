import type { AuthResponse, APIKey, Project, Vulnerability, DiffResult, User, ScanSummary } from "./types";

const BASE = "";

function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("token");
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${BASE}${path}`, { ...options, headers });

  if (res.status === 401) {
    // token expiré — redirect propre sans boucle
    if (typeof window !== "undefined" && !window.location.pathname.includes("/login")) {
      clearAuth();
      window.location.href = "/login?expired=1";
    }
    throw new Error("Session expired");
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error ?? `HTTP ${res.status}`);
  }
  return res.json();
}

function clearAuth() {
  localStorage.removeItem("token");
  localStorage.removeItem("user");
}

// Auth
export const authApi = {
  register: (org_name: string, email: string, password: string) =>
    request<AuthResponse>("/api/v1/auth/register", {
      method: "POST",
      body: JSON.stringify({ org_name, email, password }),
    }),
  login: (email: string, password: string) =>
    request<AuthResponse>("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),
  me: () => request<User>("/api/v1/auth/me"),
  changePassword: (current_password: string, new_password: string) =>
    request<void>("/api/v1/auth/password", {
      method: "PUT",
      body: JSON.stringify({ current_password, new_password }),
    }),
};

// Projects
export const projectsApi = {
  list: () => request<Project[]>("/api/v1/projects"),
  diff: (name: string) => request<DiffResult>(`/api/v1/projects/diff?name=${encodeURIComponent(name)}`),
  scans: (name: string) => request<ScanSummary[]>(`/api/v1/projects/scans?name=${encodeURIComponent(name)}`),
  scanVulnerabilities: (scanId: number) => request<Vulnerability[]>(`/api/v1/scans/${scanId}/vulnerabilities`),
};

export interface VulnPage {
  data: Vulnerability[];
  total: number;
  page: number;
  limit: number;
  /** per-severity counts, ignoring the severity filter */
  counts: Partial<Record<string, number>>;
}

// Vulnerabilities
export const vulnApi = {
  list: (page = 1, limit = 100, severity = "", project = "", q = "") =>
    request<VulnPage>(`/api/v1/vulnerabilities?page=${page}&limit=${limit}${severity ? `&severity=${severity}` : ""}${project ? `&project=${encodeURIComponent(project)}` : ""}${q ? `&q=${encodeURIComponent(q)}` : ""}`),
};

// Members
export const membersApi = {
  list: () => request<User[]>("/api/v1/members"),
  invite: (email: string, role: string) =>
    request<void>("/api/v1/members/invite", {
      method: "POST",
      body: JSON.stringify({ email, role }),
    }),
  updateRole: (id: number, role: string) =>
    request<void>(`/api/v1/members/${id}/role`, {
      method: "PUT",
      body: JSON.stringify({ role }),
    }),
  remove: (id: number) =>
    request<void>(`/api/v1/members/${id}`, { method: "DELETE" }),
};

// API Keys
export const apiKeysApi = {
  list: () => request<APIKey[]>("/api/v1/api-keys"),
  create: (name: string) =>
    request<APIKey>("/api/v1/api-keys", {
      method: "POST",
      body: JSON.stringify({ name }),
    }),
  revoke: (id: number) =>
    request<void>(`/api/v1/api-keys/${id}`, { method: "DELETE" }),
};
