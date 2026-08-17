/**
 * The simulated control engine + protected target.
 *
 * Rule evaluation order is deliberately: pre-installed (unrelated) rules first,
 * then the applied candidate. That ordering is what lets a legacy edge filter
 * shadow a candidate and produce genuinely unattributable blocking.
 */
import { SEED_INSTANCES } from './instances.js';
import { sha256, uuid, nowIso } from '../../lib/digest.js';

const instances = new Map();

export function resetInstances() {
  instances.clear();
  for (const seed of SEED_INSTANCES) {
    instances.set(seed.instance_id, {
      ...structuredClone(seed),
      applications: [], // active candidate applications
      transactions: [], // rolling transaction log
    });
  }
}
resetInstances();

export function listInstances() {
  return [...instances.values()].map(describeInstance);
}

export function getInstance(id) {
  return instances.get(id) || null;
}

export function describeInstance(instance) {
  return {
    instance_id: instance.instance_id,
    control: instance.control,
    configuration_fingerprint: instance.configuration_fingerprint,
    isolation: instance.isolation,
    observation: instance.advertised_observation,
    protected_target: { name: instance.app.name },
    active_applications: instance.applications.map((a) => ({
      application_id: a.application_id,
      policy_ref: a.policy_ref,
      candidate_id: a.candidate_id,
      candidate_digest: a.candidate_digest,
      rule_ids: a.rules.map((r) => r.rule_id),
      applied_at: a.applied_at,
    })),
    preinstalled_rule_ids: instance.preinstalled_rules.map((r) => r.rule_id),
    transaction_count: instance.transactions.length,
  };
}

/** Apply an already-translated native candidate artifact. No translation here. */
export function applyCandidate(instance, { policy_ref, candidate_id, candidate_digest, artifact }) {
  if (instance.fault_injection.apply === 'indeterminate') {
    return {
      ok: false,
      error: {
        code: 'apply-indeterminate',
        message: 'rule commit timed out before acknowledgement; resulting policy state is unknown',
        state: 'unknown',
      },
    };
  }
  const rules = artifact?.rules ?? [];
  if (!Array.isArray(rules) || rules.length === 0) {
    return { ok: false, error: { code: 'invalid-artifact', message: 'candidate artifact declares no rules', state: 'unchanged' } };
  }
  for (const rule of rules) {
    try {
      new RegExp(rule.pattern, 'i');
    } catch {
      return { ok: false, error: { code: 'invalid-artifact', message: `rule ${rule.rule_id} has an uncompilable pattern`, state: 'unchanged' } };
    }
  }

  const application = {
    application_id: `app_${uuid().slice(0, 8)}`,
    policy_ref,
    candidate_id,
    candidate_digest,
    rules,
    applied_at: nowIso(),
  };
  instance.applications.push(application);
  return { ok: true, application, control_state: policyState(instance, policy_ref) };
}

export function removeApplication(instance, applicationId) {
  const index = instance.applications.findIndex((a) => a.application_id === applicationId);
  if (index === -1) {
    return { ok: false, error: { code: 'application-not-found', message: 'no such application on this instance', state: 'unknown' } };
  }
  const [removed] = instance.applications.splice(index, 1);
  return {
    ok: true,
    reset_evidence: {
      application_id: removed.application_id,
      removed_at: nowIso(),
      removed_rule_ids: removed.rules.map((r) => r.rule_id),
      residual_application_ids: instance.applications.map((a) => a.application_id),
      control_state: policyState(instance, removed.policy_ref),
    },
  };
}

export function policyState(instance, policyRef) {
  const applications = instance.applications.filter((a) => a.policy_ref === policyRef);
  return {
    instance_id: instance.instance_id,
    policy_ref: policyRef,
    control: instance.control,
    configuration_fingerprint: instance.configuration_fingerprint,
    active_application_ids: applications.map((a) => a.application_id),
    active_candidate_digests: applications.map((a) => a.candidate_digest),
    active_rule_ids: [
      ...instance.preinstalled_rules.map((r) => r.rule_id),
      ...applications.flatMap((a) => a.rules.map((r) => r.rule_id)),
    ],
    candidate_absent: applications.length === 0,
    observed_at: nowIso(),
  };
}

/**
 * Request normalization applied before matching, equivalent to a rule chain's
 * `t:urlDecodeUni,t:lowercase` transformations. Without it, percent-encoded
 * payloads would trivially evade every signature.
 */
function urlDecode(value) {
  if (!value) return '';
  try {
    return decodeURIComponent(String(value).replace(/\+/g, ' '));
  } catch {
    return String(value);
  }
}

function subjectFor(target, request) {
  const uri = request.query ? `${request.path}?${urlDecode(request.query)}` : request.path;
  const body = urlDecode(request.body ?? '');
  const headers = Object.entries(request.headers ?? {})
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n');
  switch (target) {
    case 'REQUEST_URI':
      return uri;
    case 'REQUEST_BODY':
      return body;
    case 'REQUEST_HEADERS':
      return headers;
    default:
      return `${uri}\n${body}\n${headers}`;
  }
}

/** Send one request through the control and, if allowed, on to the target. */
export function sendTraffic(instance, request) {
  const transaction_id = `txn_${uuid().slice(0, 12)}`;
  const activeRules = [
    ...instance.preinstalled_rules.map((r) => ({ rule: r, source: 'preinstalled', application: null })),
    ...instance.applications.flatMap((a) => a.rules.map((r) => ({ rule: r, source: 'candidate', application: a }))),
  ];

  let hit = null;
  for (const entry of activeRules) {
    const subject = subjectFor(entry.rule.target, request);
    if (new RegExp(entry.rule.pattern, 'i').test(subject)) {
      hit = entry;
      break;
    }
  }

  const attributionAvailable = instance.attribution_enabled && hit?.rule.attribution !== false;

  const control = {
    engine: instance.control.technology,
    version: instance.control.version,
    instance_id: instance.instance_id,
    decision: hit ? 'deny' : 'allow',
    status_code: hit ? hit.rule.status ?? 403 : null,
    // With attribution disabled the control reports only that *something*
    // rejected the request — the hallmark of a non-attributable block.
    matched_rule_id: hit && attributionAvailable ? hit.rule.rule_id : null,
    matched_policy_ref: hit && attributionAvailable ? hit.application?.policy_ref ?? 'baseline-policy' : null,
    active_candidate_digest: hit && attributionAvailable ? hit.application?.candidate_digest ?? null : null,
    attribution_available: Boolean(hit) && attributionAvailable,
    active_application_ids: instance.applications.map((a) => a.application_id),
  };

  let target = null;
  if (!hit) {
    const probe = `${request.path}${request.query ? `?${urlDecode(request.query)}` : ''}\n${urlDecode(request.body ?? '')}`;
    const markers = [];
    const onVulnerableEndpoint = new RegExp(instance.app.vulnerable_endpoint, 'i').test(request.path);
    if (onVulnerableEndpoint && new RegExp(instance.app.vulnerable_behavior_signature, 'i').test(probe)) {
      markers.push('vulnerable-behavior');
    }
    if (new RegExp(instance.app.discriminator_signature, 'i').test(request.path)) markers.push('discriminator-target');
    target = {
      app: instance.app.name,
      receipt_id: `rcpt_${uuid().slice(0, 8)}`,
      reached: true,
      status_code: 200,
      markers,
    };
  }

  const transaction = {
    transaction_id,
    instance_id: instance.instance_id,
    received_at: nowIso(),
    request: { method: request.method, path: request.path, query: request.query ?? null, body_present: Boolean(request.body) },
    control,
    target,
    // Deliberately secret-bearing: downstream redaction must strip this before
    // it can reach a result, prose summary, or reference bundle (AC-13).
    simulator_api_key: 'sk-sim-live-9d2f41c0a77b4e18',
  };
  instance.transactions.push(transaction);
  if (instance.transactions.length > 500) instance.transactions.shift();
  return transaction;
}

export function artifactDigest(artifact) {
  return sha256(artifact);
}
