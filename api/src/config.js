export const PORT = Number(process.env.API_PORT ?? 8088);

/** Control plane and BAS vendor both live in the external-execution simulator today. */
const SIM_BASE = process.env.SIM_BASE_URL ?? 'http://localhost:8099';
export const CONTROL_PLANE_BASE_URL = process.env.CONTROL_PLANE_BASE_URL ?? SIM_BASE;
export const SAFEBREACH_BASE_URL = process.env.SAFEBREACH_BASE_URL ?? SIM_BASE;

export const SAFEBREACH_POLL_INTERVAL_MS = Number(process.env.SAFEBREACH_POLL_INTERVAL_MS ?? 40);
export const SAFEBREACH_TIMEOUT_MS = Number(process.env.SAFEBREACH_TIMEOUT_MS ?? 5000);

/** Deliberate per-step pacing so the pipeline is legible in the UI. */
export const STEP_PACING_MS = Number(process.env.STEP_PACING_MS ?? 90);

export const ALGORITHM_VERSION = 'defense-validation-engine@1.0.0';

/**
 * Stand-in for workload identity / OIDC (§13.1). Tokens map to roles; the API
 * enforces RBAC on every route.
 */
export const TOKENS = new Map([
  ['dev-submitter-token', { subject: 'orchestrator@janus', roles: ['submitter', 'viewer'] }],
  ['dev-operator-token', { subject: 'validation-operator@janus', roles: ['operator', 'viewer'] }],
  ['dev-viewer-token', { subject: 'reviewer@janus', roles: ['viewer'] }],
]);

/** Only these environments may ever be addressed by an adapter (§13.5). */
export const PERMITTED_CONTEXT_ENVIRONMENTS = ['non-prod'];

/**
 * Adapter allowlists (§17). Requests carry their own context descriptor, so
 * these are the deployment's statement about which adapters it will actually
 * operate — a payload cannot introduce a new one.
 */
export const PERMITTED_CONTROL_ADAPTERS = ['control-adapter-modsecurity:1'];
export const PERMITTED_RUNNER_ADAPTERS = ['runner-adapter-safebreach:1', 'runner-adapter-local-http:1'];
