const BASE_URL = "http://127.0.0.1:8822";

function authHeader(): Record<string, string> {
  const token = localStorage.getItem("token");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export async function login(username: string, password: string) {
  const body = new URLSearchParams({ username, password });
  const res = await fetch(`${BASE_URL}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!res.ok) throw new Error("Invalid credentials");
  const data = await res.json();
  localStorage.setItem("token", data.access_token);
  localStorage.setItem("role", data.role);
  return data;
}

export function logout() {
  localStorage.removeItem("token");
  localStorage.removeItem("role");
}

export function isAuthed() {
  return !!localStorage.getItem("token");
}

export async function getDashboardStats() {
  const res = await fetch(`${BASE_URL}/api/dashboard/stats`, { headers: authHeader() });
  if (!res.ok) throw new Error("Failed to load dashboard stats");
  return res.json();
}

export async function listScans() {
  const res = await fetch(`${BASE_URL}/api/scans`, { headers: authHeader() });
  if (!res.ok) throw new Error("Failed to load scans");
  return res.json();
}

export async function getScan(id: number) {
  const res = await fetch(`${BASE_URL}/api/scan/${id}`, { headers: authHeader() });
  if (!res.ok) throw new Error("Failed to load scan");
  return res.json();
}

export async function uploadScan(projectName: string, file: File) {
  const form = new FormData();
  form.append("project_name", projectName);
  form.append("file", file);
  const res = await fetch(`${BASE_URL}/api/scan/upload`, {
    method: "POST",
    headers: authHeader(),
    body: form,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Scan failed" }));
    throw new Error(err.detail || "Scan failed");
  }
  return res.json();
}

export async function scanRepository(projectName: string, repoUrl: string) {
  const form = new FormData();
  form.append("project_name", projectName);
  form.append("repo_url", repoUrl);
  const res = await fetch(`${BASE_URL}/api/scan/repository`, {
    method: "POST",
    headers: authHeader(),
    body: form,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Repository scan failed" }));
    throw new Error(err.detail || "Repository scan failed");
  }
  return res.json();
}

export async function getMitreMapping(scanId: number) {
  const res = await fetch(`${BASE_URL}/api/scan/${scanId}/mitre`, { headers: authHeader() });
  if (!res.ok) throw new Error("Failed to load MITRE mapping");
  return res.json();
}

export async function getDependencyGraph(scanId: number) {
  const res = await fetch(`${BASE_URL}/api/scan/${scanId}/dependency-graph`, { headers: authHeader() });
  if (!res.ok) throw new Error("Failed to load dependency graph");
  return res.json();
}

export async function listSchedules() {
  const res = await fetch(`${BASE_URL}/api/schedule`, { headers: authHeader() });
  if (!res.ok) throw new Error("Failed to load schedules");
  return res.json();
}

export async function createSchedule(projectName: string, repoUrl: string, intervalMinutes: number) {
  const form = new FormData();
  form.append("project_name", projectName);
  form.append("repo_url", repoUrl);
  form.append("interval_minutes", String(intervalMinutes));
  const res = await fetch(`${BASE_URL}/api/schedule`, { method: "POST", headers: authHeader(), body: form });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Failed to create schedule" }));
    throw new Error(err.detail || "Failed to create schedule");
  }
  return res.json();
}

export async function deleteSchedule(id: number) {
  const res = await fetch(`${BASE_URL}/api/schedule/${id}`, { method: "DELETE", headers: authHeader() });
  if (!res.ok) throw new Error("Failed to delete schedule");
  return res.json();
}

export function scanLogSocketUrl(scanId: number) {
  const wsBase = BASE_URL.replace("http://", "ws://").replace("https://", "wss://");
  return `${wsBase}/ws/scan/${scanId}/logs`;
}

export function reportUrl(scanId: number, fmt: string) {
  const token = localStorage.getItem("token");
  return `${BASE_URL}/api/scan/${scanId}/report?fmt=${fmt}&_t=${token}`;
}

export async function downloadReport(scanId: number, fmt: string, projectLabel: string) {
  const res = await fetch(`${BASE_URL}/api/scan/${scanId}/report?fmt=${fmt}`, { headers: authHeader() });
  if (!res.ok) throw new Error("Failed to generate report");
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  const ext = fmt === "markdown" ? "md" : fmt;
  a.href = url;
  a.download = `${projectLabel}-report.${ext}`;
  a.click();
  URL.revokeObjectURL(url);
}
