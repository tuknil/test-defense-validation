/**
 * Contract validation for SubmitDefenseValidationRequest@1.
 *
 * The request is self-contained: the requestor supplies the exact candidate
 * artifact, both suites, the validation context descriptor, the profile, and
 * the policy inline. This service resolves nothing by ID and maintains no
 * registry, so the payload is the sole authority on what is being validated.
 *
 * Everything here is untrusted material (§13.4). Only typed, allowlisted fields
 * are interpreted; anything unrecognised is refused rather than ignored, so a
 * payload cannot smuggle in fields that alter policy, scope, or expected
 * outcomes.
 */
export const CONTRACT_ID = 'defense-validation@1.0';

/** Hard service limits, independent of whatever the supplied policy claims (§13.7). */
export const LIMITS = {
  maxRules: 50,
  maxAttackCases: 64,
  maxBenignCases: 64,
  maxPatternLength: 512,
  maxStringLength: 4096,
};

export const TERMINAL_STATES = [
  'validated',
  'failed-to-block',
  'unsafe',
  'environment-invalid',
  'inconclusive',
  'scope-declined',
  'malfunction',
];

export const ERROR_CATEGORIES = [
  'invalid-input',
  'artifact-resolution-failure',
  'invalid-policy-profile',
  'candidate-application-failure',
  'runner-failure',
  'observation-correlation-failure',
  'persistence-failure',
  'result-assembly-failure',
];

const str = (extra = {}) => ({ type: 'string', ...extra });

/**
 * Identifiers that end up in an adapter's URL path. Constrained to a safe
 * character set so a payload cannot steer an adapter off its route — no
 * slashes, no dot-segments, nothing percent-encodable into either (§13.4).
 */
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]*$/;
const routeId = (extra = {}) => ({ type: 'string', pattern: ID_PATTERN, maxLength: 200, ...extra });
const bool = (extra = {}) => ({ type: 'boolean', ...extra });
const num = (extra = {}) => ({ type: 'number', ...extra });
const strList = (extra = {}) => ({ array: str(), ...extra });

const REQUEST_SPEC = {
  object: {
    contract_id: { const: CONTRACT_ID },

    control_candidate: {
      object: {
        control_candidate_id: str(),
        vulnerability_id: str({ optional: true }),
        target_control_class: { enum: ['waf'] },
        target_technology: str(),
        // Optional: when supplied, the service verifies it against the digest
        // it derives from the artifact itself.
        digest: str({ optional: true }),
        summary: str({ optional: true }),
        translation: {
          object: {
            translated_candidate_result_id: str(),
            source_mitigation_candidate_id: str({ optional: true }),
            translated_at: str({ optional: true }),
          },
        },
        artifact: {
          object: {
            syntax: str(),
            rules: {
              minItems: 1,
              maxItems: LIMITS.maxRules,
              array: {
                object: {
                  rule_id: str(),
                  target: { enum: ['ANY', 'REQUEST_URI', 'REQUEST_BODY', 'REQUEST_HEADERS'] },
                  operator: { enum: ['rx'] },
                  pattern: str({ maxLength: LIMITS.maxPatternLength }),
                  action: { enum: ['deny'] },
                  status: num({ optional: true }),
                },
              },
            },
          },
        },
      },
    },

    attack_suite: {
      object: {
        attack_suite_id: str(),
        vulnerability_id: str({ optional: true }),
        source: str({ optional: true }),
        modality: str(),
        representativeness_limits: { ...strList({ optional: true }) },
        cases: {
          minItems: 1,
          maxItems: LIMITS.maxAttackCases,
          array: {
            object: {
              case_id: str(),
              proof_strength: { enum: ['direct', 'indirect'] },
              provenance: str({ optional: true }),
              expected_absent_behavior: { enum: ['reached-vulnerable-behavior', 'reached-discriminator-target'] },
              journey_steps: num({ optional: true }),
              request: { object: REQUEST_SHAPE() },
            },
          },
        },
      },
    },

    benign_suite: {
      object: {
        benign_suite_id: str(),
        curation: str({ optional: true }),
        modality: str(),
        representativeness_limits: { ...strList({ optional: true }) },
        cases: {
          minItems: 1,
          maxItems: LIMITS.maxBenignCases,
          array: {
            object: {
              case_id: str(),
              expected_outcome: { enum: ['permitted'] },
              request: { object: REQUEST_SHAPE() },
            },
          },
        },
      },
    },

    validation_context: {
      object: {
        validation_context_id: str(),
        label: str({ optional: true }),
        control: {
          object: {
            class: { enum: ['waf'] },
            technology: str(),
            version: str(),
            configuration_fingerprint: str(),
          },
        },
        candidate_application: {
          object: {
            adapter_id: routeId(),
            instance_id: routeId(),
            target_policy_ref: routeId(),
          },
        },
        execution: {
          object: {
            runner_adapter_id: routeId(),
            simulator_id: routeId({ optional: true }),
            scenario_prefix: routeId({ optional: true }),
          },
        },
        isolation: { object: { environment: str(), reset_supported: bool() } },
        observation: { object: { control_decision: bool(), protected_target_receipt: bool() } },
        fidelity: { object: { claims: strList(), evidence_refs: strList() } },
        limitations: strList({ optional: true }),
      },
    },

    validation_profile: {
      object: {
        validation_profile_id: str(),
        signed_by: str({ optional: true }),
        signature: str(),
        supported_control_classes: strList({ minItems: 1 }),
        supported_technologies: strList({ minItems: 1 }),
        supported_versions: strList({ minItems: 1 }),
        supported_case_modalities: strList({ minItems: 1 }),
        supported_proof_strengths: strList({ minItems: 1 }),
        required_observation: strList(),
        required_isolation: { object: { environment: str(), reset_supported: bool() } },
        required_fidelity_claims: strList(),
        requires_baseline_confirmation: bool(),
        requires_candidate_attribution: bool(),
      },
    },

    validation_policy: {
      object: {
        validation_policy_id: str(),
        signed_by: str({ optional: true }),
        signature: str(),
        required_attack_cases: { caseSelector: true },
        required_benign_cases: { caseSelector: true },
        require_baseline_confirmation: bool(),
        require_candidate_attribution: bool(),
        max_transient_retries: num(),
        max_cases_per_run: num(),
        retention_days: num(),
      },
    },
  },
};

function REQUEST_SHAPE() {
  return {
    method: { enum: ['GET', 'POST', 'PUT', 'DELETE', 'HEAD'] },
    path: str(),
    query: { ...str({ optional: true }), nullable: true },
    body: { ...str({ optional: true }), nullable: true },
  };
}

export function validateSubmitRequest(body) {
  const errors = [];
  check(body, REQUEST_SPEC, '', errors);
  if (errors.length === 0) crossCheck(body, errors);
  return { valid: errors.length === 0, errors: errors.slice(0, 40) };
}

function check(value, spec, path, errors) {
  const label = path || '(root)';

  if (value === undefined || value === null) {
    if (!spec.optional && !spec.nullable) errors.push({ field: label, message: 'is required' });
    return;
  }
  if (spec.const !== undefined && value !== spec.const) {
    errors.push({ field: label, message: `must be exactly "${spec.const}"` });
    return;
  }
  if (spec.enum && !spec.enum.includes(value)) {
    errors.push({ field: label, message: `must be one of: ${spec.enum.join(', ')}` });
    return;
  }
  if (spec.caseSelector) {
    const ok = value === 'all' || (Array.isArray(value) && value.every((v) => typeof v === 'string' && v.trim()));
    if (!ok) errors.push({ field: label, message: 'must be "all" or an array of case IDs' });
    return;
  }
  if (spec.type === 'string') {
    if (typeof value !== 'string' || !value.trim()) {
      errors.push({ field: label, message: 'must be a non-empty string' });
    } else if (value.length > (spec.maxLength ?? LIMITS.maxStringLength)) {
      errors.push({ field: label, message: `must be at most ${spec.maxLength ?? LIMITS.maxStringLength} characters` });
    } else if (spec.pattern && !spec.pattern.test(value)) {
      errors.push({ field: label, message: 'must contain only letters, digits, and . _ : @ - (no path separators)' });
    }
    return;
  }
  if (spec.type === 'boolean') {
    if (typeof value !== 'boolean') errors.push({ field: label, message: 'must be true or false' });
    return;
  }
  if (spec.type === 'number') {
    if (typeof value !== 'number' || !Number.isFinite(value)) errors.push({ field: label, message: 'must be a number' });
    return;
  }
  if (spec.array) {
    if (!Array.isArray(value)) {
      errors.push({ field: label, message: 'must be an array' });
      return;
    }
    if (spec.minItems && value.length < spec.minItems) errors.push({ field: label, message: `must contain at least ${spec.minItems} item(s)` });
    if (spec.maxItems && value.length > spec.maxItems) errors.push({ field: label, message: `must contain at most ${spec.maxItems} item(s)` });
    value.forEach((item, index) => check(item, spec.array, `${label}[${index}]`, errors));
    return;
  }
  if (spec.object) {
    if (typeof value !== 'object' || Array.isArray(value)) {
      errors.push({ field: label, message: 'must be an object' });
      return;
    }
    for (const [key, childSpec] of Object.entries(spec.object)) {
      check(value[key], childSpec, path ? `${path}.${key}` : key, errors);
    }
    for (const key of Object.keys(value)) {
      if (!(key in spec.object)) errors.push({ field: path ? `${path}.${key}` : key, message: 'is not permitted by the contract' });
    }
  }
}

/** Checks that need more than one field to evaluate. */
function crossCheck(body, errors) {
  const dupes = (items, key, field) => {
    const seen = new Set();
    items.forEach((item, index) => {
      if (seen.has(item[key])) errors.push({ field: `${field}[${index}].${key}`, message: `duplicates an earlier case ID "${item[key]}"` });
      seen.add(item[key]);
    });
    return seen;
  };

  const attackIds = dupes(body.attack_suite.cases, 'case_id', 'attack_suite.cases');
  const benignIds = dupes(body.benign_suite.cases, 'case_id', 'benign_suite.cases');
  dupes(body.control_candidate.artifact.rules, 'rule_id', 'control_candidate.artifact.rules');

  // A policy may only designate cases that the supplied suites actually contain.
  if (Array.isArray(body.validation_policy.required_attack_cases)) {
    for (const id of body.validation_policy.required_attack_cases) {
      if (!attackIds.has(id)) errors.push({ field: 'validation_policy.required_attack_cases', message: `"${id}" is not a case in the supplied attack suite` });
    }
  }
  if (Array.isArray(body.validation_policy.required_benign_cases)) {
    for (const id of body.validation_policy.required_benign_cases) {
      if (!benignIds.has(id)) errors.push({ field: 'validation_policy.required_benign_cases', message: `"${id}" is not a case in the supplied benign suite` });
    }
  }

  // Case requests must stay on the declared validation ingress.
  const checkPath = (request, field) => {
    if (!request.path.startsWith('/') || request.path.startsWith('//') || request.path.includes('..')) {
      errors.push({ field: `${field}.path`, message: 'must be a path relative to the declared validation ingress' });
    }
  };
  body.attack_suite.cases.forEach((c, i) => checkPath(c.request, `attack_suite.cases[${i}].request`));
  body.benign_suite.cases.forEach((c, i) => checkPath(c.request, `benign_suite.cases[${i}].request`));

  // Rule patterns must compile; an uncompilable pattern can never be applied.
  body.control_candidate.artifact.rules.forEach((rule, i) => {
    try {
      new RegExp(rule.pattern, 'i');
    } catch (err) {
      errors.push({ field: `control_candidate.artifact.rules[${i}].pattern`, message: `is not a valid regular expression: ${err.message}` });
    }
  });

  const total = body.attack_suite.cases.length + body.benign_suite.cases.length;
  if (total > body.validation_policy.max_cases_per_run) {
    errors.push({ field: 'validation_policy.max_cases_per_run', message: `is ${body.validation_policy.max_cases_per_run} but the supplied suites contain ${total} cases` });
  }
}

/** Published for discovery via GET /v1/contract. */
export const SUBMIT_REQUEST_SCHEMA = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  title: 'SubmitDefenseValidationRequest',
  description:
    'Self-contained validation request. The requestor supplies all material inline; the service resolves nothing by ID and holds no registry.',
  type: 'object',
  additionalProperties: false,
  required: ['contract_id', 'control_candidate', 'attack_suite', 'benign_suite', 'validation_context', 'validation_profile', 'validation_policy'],
  properties: toJsonSchema(REQUEST_SPEC).properties,
};

function toJsonSchema(spec) {
  if (spec.const !== undefined) return { const: spec.const };
  if (spec.enum) return { enum: spec.enum };
  if (spec.caseSelector) return { oneOf: [{ const: 'all' }, { type: 'array', items: { type: 'string' } }] };
  if (spec.type) return { type: spec.type };
  if (spec.array) {
    const items = toJsonSchema(spec.array);
    return { type: 'array', items, ...(spec.minItems ? { minItems: spec.minItems } : {}), ...(spec.maxItems ? { maxItems: spec.maxItems } : {}) };
  }
  if (spec.object) {
    const properties = {};
    const required = [];
    for (const [key, child] of Object.entries(spec.object)) {
      properties[key] = toJsonSchema(child);
      if (!child.optional) required.push(key);
    }
    return { type: 'object', additionalProperties: false, properties, required };
  }
  return {};
}
