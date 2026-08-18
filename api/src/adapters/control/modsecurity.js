/**
 * ControlAdapter for ModSecurity-class controls (§6.4).
 *
 * Applies an already-translated exact candidate. It never generates or
 * translates rules, and it only ever addresses the one instance and policy ref
 * named by the bound validation context (§13.1 least privilege).
 */
import { CONTROL_PLANE_BASE_URL } from '../../config.js';

const ADAPTER_ID = 'control-adapter-modsecurity:1';

class AdapterError extends Error {
  constructor(category, message, { stateKnown = true, detail = null } = {}) {
    super(message);
    this.category = category;
    this.stateKnown = stateKnown;
    this.detail = detail;
  }
}

/**
 * Path segments are always encoded, never interpolated raw. The contract
 * already constrains these identifiers, but encoding here means the adapter
 * cannot be steered off its route even if a future field slips through
 * unvalidated (§13.4, §13.5).
 */
const seg = (value) => encodeURIComponent(String(value));

async function call(path, init = {}) {
  let response;
  try {
    response = await fetch(`${CONTROL_PLANE_BASE_URL}${path}`, {
      ...init,
      headers: { 'Content-Type': 'application/json', ...(init.headers ?? {}) },
    });
  } catch (err) {
    throw new AdapterError('candidate-application-failure', `control plane unreachable: ${err.message}`, { stateKnown: false });
  }
  const text = await response.text();
  const body = text ? JSON.parse(text) : null;
  return { ok: response.ok, status: response.status, body };
}

function assertNonProd(context) {
  if (context.isolation.environment !== 'non-prod') {
    throw new AdapterError('candidate-application-failure', 'adapter identity is scoped to non-production contexts only');
  }
}

export const modsecurityControlAdapter = {
  adapter_id: ADAPTER_ID,

  /** Probe live control state for the context evaluator. */
  async describeContext(context) {
    const { instance_id } = context.candidate_application;
    const { ok, body } = await call(`/waf/v1/instances/${seg(instance_id)}`);
    if (!ok) throw new AdapterError('candidate-application-failure', body?.error?.message ?? 'control instance could not be described');
    return body;
  },

  /** EstablishBaseline: prove the candidate is absent before baseline trials. */
  async establishBaseline(context) {
    assertNonProd(context);
    const { instance_id, target_policy_ref } = context.candidate_application;
    const { ok, body } = await call(`/waf/v1/instances/${seg(instance_id)}/policies/${seg(target_policy_ref)}`);
    if (!ok) throw new AdapterError('candidate-application-failure', body?.error?.message ?? 'baseline control state could not be read', { stateKnown: false });
    return {
      state: body.candidate_absent ? 'candidate-absent' : 'candidate-present',
      state_established: body.candidate_absent === true,
      active_rule_ids: body.active_rule_ids,
      active_candidate_digests: body.active_candidate_digests,
      observed_at: body.observed_at,
      raw: body,
    };
  },

  /** Apply the exact candidate artifact. */
  async apply(context, candidate) {
    assertNonProd(context);
    const { instance_id, target_policy_ref } = context.candidate_application;
    const { ok, status, body } = await call(`/waf/v1/instances/${seg(instance_id)}/policies/${seg(target_policy_ref)}/rules`, {
      method: 'POST',
      body: JSON.stringify({
        candidate_id: candidate.control_candidate_id,
        candidate_digest: candidate.digest,
        artifact: candidate.artifact,
      }),
    });
    if (!ok) {
      // A 503 with `state: unknown` is the case that must never be retried
      // blindly (§12.2): actual control state has to be reconciled first.
      const stateKnown = body?.error?.state !== 'unknown';
      throw new AdapterError('candidate-application-failure', body?.error?.message ?? `apply failed with status ${status}`, {
        stateKnown,
        detail: body?.error ?? null,
      });
    }
    return {
      application_id: body.application_id,
      instance_id: body.instance_id,
      policy_ref: body.policy_ref,
      candidate_id: body.candidate_id,
      candidate_digest: body.candidate_digest,
      applied_rule_ids: body.applied_rule_ids,
      applied_at: body.applied_at,
      raw: body,
    };
  },

  /** VerifyApplied: prove the exact expected digest is what is live. */
  async verifyApplied(context, application, expectedDigest) {
    const { instance_id, target_policy_ref } = context.candidate_application;
    const { ok, body } = await call(`/waf/v1/instances/${seg(instance_id)}/policies/${seg(target_policy_ref)}`);
    if (!ok) throw new AdapterError('candidate-application-failure', 'applied control state could not be verified', { stateKnown: false });
    const digestActive = body.active_candidate_digests.includes(expectedDigest);
    const applicationActive = body.active_application_ids.includes(application.application_id);
    return {
      state: digestActive && applicationActive ? 'candidate-present-verified' : 'candidate-state-unverified',
      state_established: digestActive && applicationActive,
      expected_digest: expectedDigest,
      active_candidate_digests: body.active_candidate_digests,
      active_rule_ids: body.active_rule_ids,
      observed_at: body.observed_at,
      raw: body,
    };
  },

  /** RemoveOrReset, always attempted, always evidenced. */
  async removeOrReset(context, application) {
    const { instance_id } = context.candidate_application;
    const { ok, body } = await call(`/waf/v1/instances/${seg(instance_id)}/applications/${seg(application.application_id)}`, { method: 'DELETE' });
    if (!ok) {
      return { removed: false, error: body?.error?.message ?? 'candidate removal failed', raw: body };
    }
    return { removed: true, ...body };
  },
};

export { AdapterError };
