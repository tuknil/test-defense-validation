const CONFIG = window.__DV_CONFIG__ ?? { apiBaseUrl: 'http://localhost:8088', simBaseUrl: 'http://localhost:8099' };

export const IDENTITIES = [
  { token: 'dev-submitter-token', label: 'orchestrator@janus (submitter)' },
  { token: 'dev-operator-token', label: 'validation-operator@janus (operator)' },
  { token: 'dev-viewer-token', label: 'reviewer@janus (viewer)' },
];

export function currentToken() {
  return localStorage.getItem('dv.token') ?? IDENTITIES[0].token;
}

export function setToken(token) {
  localStorage.setItem('dv.token', token);
}

async function request(path, init = {}) {
  const response = await fetch(`${CONFIG.apiBaseUrl}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${currentToken()}`, ...(init.headers ?? {}) },
  });
  const text = await response.text();
  const body = text ? JSON.parse(text) : null;
  if (!response.ok) {
    const error = new Error(body?.error?.message ?? `request failed (${response.status})`);
    error.status = response.status;
    error.code = body?.error?.code;
    error.details = body?.error?.details;
    throw error;
  }
  return body;
}

export const api = {
  baseUrl: CONFIG.apiBaseUrl,
  simUrl: CONFIG.simBaseUrl,
  health: () => request('/health'),
  contract: () => request('/v1/contract'),
  examples: () => request('/v1/example-payloads'),
  validate: (body) => request('/v1/defense-validation-runs/validate', { method: 'POST', body: JSON.stringify(body) }),
  runs: (query = '') => request(`/v1/defense-validation-runs${query}`),
  run: (id) => request(`/v1/defense-validation-runs/${encodeURIComponent(id)}`),
  result: (id) => request(`/v1/defense-validation-results/${encodeURIComponent(id)}`),
  bundle: (id) => request(`/v1/defense-validation-results/${encodeURIComponent(id)}/reference-bundle`),
  evidence: (digest) => request(`/v1/evidence/${encodeURIComponent(digest.replace('sha256:', ''))}`),
  ledger: (query = '') => request(`/v1/ledger${query}`),
  events: () => request('/v1/events'),
  audit: (runId) => request(`/v1/audit${runId ? `?run_id=${encodeURIComponent(runId)}` : ''}`),
  metrics: () => request('/v1/metrics'),
  submit: (body, { force = false } = {}) =>
    request(`/v1/defense-validation-runs${force ? '?force=true' : ''}`, { method: 'POST', body: JSON.stringify(body) }),
};

export async function simHealth() {
  const response = await fetch(`${CONFIG.simBaseUrl}/health`);
  if (!response.ok) throw new Error('simulator unavailable');
  return response.json();
}
