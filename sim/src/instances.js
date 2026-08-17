/**
 * Simulated dev-equivalent control instances.
 *
 * Each instance is a WAF engine in front of a protected non-prod target app.
 * The `defense-validation` service does NOT read this file — it only observes
 * these instances over HTTP, exactly as it would observe a real lab.
 *
 * `advertised_observation` is what the instance *claims* it can observe.
 * `attribution_enabled` is what actually happens at request time. Keeping the
 * two separate is what makes "declared observability that is not realised at
 * runtime" (CONF-06) an honest, discoverable condition rather than a fixture.
 */

const PAYMENTS_APP = {
  name: 'payments-dev-equivalent',
  // The vulnerable code path lives behind this endpoint only. Reaching the
  // vulnerable behavior requires BOTH the vulnerable endpoint *and* a payload
  // that drives the injection — a payload alone proves nothing, because the
  // same string sent elsewhere never touches the vulnerable query builder.
  vulnerable_endpoint: '^/api/orders',
  vulnerable_behavior_signature: "('\\s*or\\s*'?1'?\\s*=\\s*'?1|union\\s+select|;\\s*drop\\s+table)",
  // A stand-in endpoint for indirect proof suites. It observes the same traffic
  // shape at the edge but never exercises the vulnerable code path, which is
  // exactly why blocking it is weaker evidence.
  discriminator_signature: '^/internal/probe/',
};

// A pre-existing, unrelated deny rule that blocks the same traffic shape but
// reports no attribution. Used to demonstrate baseline contamination (CONF-09).
const GENERIC_LEGACY_RULE = {
  rule_id: 'legacy-edge-filter-0001',
  target: 'ANY',
  operator: 'rx',
  pattern: "('\\s*or\\s*'?1'?\\s*=\\s*'?1|union\\s+select|;\\s*drop\\s+table)",
  action: 'deny',
  status: 403,
  attribution: false,
};

export const SEED_INSTANCES = [
  {
    instance_id: 'waf-payments-dev',
    control: { class: 'waf', technology: 'modsecurity', version: '3.0.12' },
    configuration_fingerprint: 'sha256:cfg-payments-dev-v3',
    isolation: { environment: 'non-prod', reset_supported: true },
    advertised_observation: { control_decision: true, protected_target_receipt: true },
    attribution_enabled: true,
    preinstalled_rules: [],
    fault_injection: {},
    app: PAYMENTS_APP,
  },
  {
    instance_id: 'waf-payments-legacy',
    control: { class: 'waf', technology: 'modsecurity', version: '2.9.7' },
    configuration_fingerprint: 'sha256:cfg-payments-legacy-v1',
    isolation: { environment: 'non-prod', reset_supported: true },
    advertised_observation: { control_decision: true, protected_target_receipt: true },
    attribution_enabled: true,
    preinstalled_rules: [],
    fault_injection: {},
    app: PAYMENTS_APP,
  },
  {
    instance_id: 'waf-checkout-noattrib',
    control: { class: 'waf', technology: 'modsecurity', version: '3.0.12' },
    configuration_fingerprint: 'sha256:cfg-checkout-v2',
    isolation: { environment: 'non-prod', reset_supported: true },
    // Claims full observability…
    advertised_observation: { control_decision: true, protected_target_receipt: true },
    // …but emits generic rejections with no rule/candidate attribution.
    attribution_enabled: false,
    preinstalled_rules: [],
    fault_injection: {},
    app: PAYMENTS_APP,
  },
  {
    instance_id: 'waf-checkout-contaminated',
    control: { class: 'waf', technology: 'modsecurity', version: '3.0.12' },
    configuration_fingerprint: 'sha256:cfg-checkout-contaminated-v1',
    isolation: { environment: 'non-prod', reset_supported: true },
    advertised_observation: { control_decision: true, protected_target_receipt: true },
    attribution_enabled: false,
    preinstalled_rules: [GENERIC_LEGACY_RULE],
    fault_injection: {},
    app: PAYMENTS_APP,
  },
  {
    instance_id: 'waf-payments-faulty',
    control: { class: 'waf', technology: 'modsecurity', version: '3.0.12' },
    configuration_fingerprint: 'sha256:cfg-payments-dev-v3',
    isolation: { environment: 'non-prod', reset_supported: true },
    advertised_observation: { control_decision: true, protected_target_receipt: true },
    attribution_enabled: true,
    preinstalled_rules: [],
    // Rule commit times out; the resulting policy state is genuinely unknown.
    fault_injection: { apply: 'indeterminate' },
    app: PAYMENTS_APP,
  },
  {
    instance_id: 'waf-payments-drift',
    control: { class: 'waf', technology: 'modsecurity', version: '3.0.12' },
    // Drifted away from the fingerprint the approved context descriptor claims.
    configuration_fingerprint: 'sha256:cfg-payments-dev-v4-UNAPPROVED',
    isolation: { environment: 'non-prod', reset_supported: true },
    advertised_observation: { control_decision: true, protected_target_receipt: true },
    attribution_enabled: true,
    preinstalled_rules: [],
    fault_injection: {},
    app: PAYMENTS_APP,
  },
];
