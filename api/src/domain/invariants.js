/**
 * Result invariant checks (§2.4, §8.2, §23).
 *
 * Run immediately before the result is made durable. A violation means the
 * runtime cannot emit a trustworthy domain result, so the run becomes
 * `malfunction` rather than shipping an unsound verdict.
 */
/**
 * Prohibited *claims*, not prohibited words. The prose is required to state the
 * capability boundary, so "separate production-safety consideration applies" has
 * to pass while "this candidate is production-safe" must not. Each pattern
 * therefore matches an affirmative construction.
 */
const OVERCLAIM_PATTERNS = [
  /\b(?:is|are|was|were|deemed|confirmed|proven|considered)\s+(?:production[-\s]safe|safe\s+(?:for|to)\s+(?:deploy\w*|production|release))/i,
  /\b(?:approved|authorized|cleared|ready|eligible)\s+for\s+(?:deployment|production|rollout|release)\b/i,
  /\bno\s+(?:performance|slo|latency|availability)\s+impact\b/i,
  /\b(?:universal|complete|full|total)(?:ly)?\s+(?:prevent\w*|protect\w*|block\w*|mitigat\w*)/i,
  /\bbypass[-\s]resistant\b/i,
  /\b(?:establishes|provides|demonstrates|proves)\s+(?:\w+\s+){0,2}coverage\b/i,
  /\bcoverage\s+(?:is|was)\s+(?:established|achieved|demonstrated|proven)\b/i,
  /\b(?:blast\s+radius|production\s+impact)\s+(?:is|was)\s+\w+/i,
];

const SECRET_KEY_PATTERN = /(api[_-]?key|secret|token|password|authorization|cookie|credential|bearer)/i;
const SECRET_VALUE_PATTERN = /\bsk-[a-z0-9-]{8,}\b|\bBearer\s+[A-Za-z0-9._-]{10,}/i;

export function checkResultInvariants(result) {
  const violations = [];
  const fail = (code, detail) => violations.push({ code, detail });

  /* Exact candidate binding (§2.4, AC-1) */
  if (!result.subject?.control_candidate_id) fail('candidate-binding-missing', 'result does not name a control candidate');
  if (!result.subject?.candidate_digest?.startsWith('sha256:')) fail('candidate-digest-missing', 'result does not bind an exact candidate digest');
  if (!result.input_bindings?.translated_candidate_result_id) fail('translation-ancestry-missing', 'result does not bind the translation result');

  /* Proof strength always explicit (§2.4, AC-2) */
  if (!result.proof_strength) fail('proof-strength-missing', 'aggregate proof strength is not stated');
  for (const observation of result.attack_observations ?? []) {
    if (!observation.proof_strength) fail('case-proof-strength-missing', `attack case ${observation.case_id} does not state proof strength`);
  }

  /* Context validity precedes candidate judgment (§7.1, AC-3) */
  const candidateJudgments = ['validated', 'failed-to-block', 'unsafe'];
  if (candidateJudgments.includes(result.terminal_state) && result.context_assessment?.status !== 'valid') {
    fail('candidate-judgment-without-valid-context', `terminal state "${result.terminal_state}" requires a valid context assessment`);
  }

  /* Candidate state integrity (§7.2, AC-4) */
  if (candidateJudgments.includes(result.terminal_state) && !result.candidate_application?.state_established) {
    fail('candidate-judgment-without-established-state', `terminal state "${result.terminal_state}" requires established candidate application state`);
  }

  /* `validated` requires complete required evidence (AC-5, AC-6) */
  if (result.terminal_state === 'validated') {
    const requiredAttack = result.attack_observations.filter((o) => o.required);
    const requiredBenign = result.benign_observations.filter((o) => o.required);
    if (requiredAttack.length === 0) fail('validated-without-attack-evidence', 'validated requires at least one required attack case');
    if (requiredBenign.length === 0) fail('validated-without-benign-evidence', 'validated requires at least one required benign case');
    for (const o of requiredAttack) {
      if (o.conclusion !== 'blocked-as-required') fail('validated-with-unblocked-attack', `attack case ${o.case_id} concluded "${o.conclusion}"`);
    }
    for (const o of requiredBenign) {
      if (o.conclusion !== 'preserved') fail('validated-with-benign-not-preserved', `benign case ${o.case_id} concluded "${o.conclusion}"`);
    }
    if (result.proof_strength === 'not-established') fail('validated-without-proof-strength', 'validated cannot carry proof strength "not-established"');
  }

  /* `unsafe` governs; both sets of findings retained (§2.4, AC-10) */
  if (result.terminal_state === 'unsafe') {
    const regressed = result.benign_observations.filter((o) => o.required && o.conclusion === 'regressed');
    if (regressed.length === 0) fail('unsafe-without-benign-regression', 'unsafe requires at least one required benign regression');
  }

  /* Negative observations are never discarded (§11.2) */
  if (result.terminal_state === 'unsafe' || result.terminal_state === 'failed-to-block') {
    if ((result.attack_observations ?? []).length === 0) fail('negative-observations-discarded', 'attack observations were not retained');
  }

  /* No overclaim (§2.4, AC-12) and no secrets (AC-13) */
  const prose = result.prose_summary ?? '';
  for (const pattern of OVERCLAIM_PATTERNS) {
    if (pattern.test(prose)) fail('prose-overclaim', `prose summary matches a prohibited claim pattern: ${pattern}`);
  }
  const leaks = findSecrets(result);
  for (const path of leaks) fail('secret-material-present', `potential secret material at ${path}`);

  return { ok: violations.length === 0, violations };
}

export function findSecrets(value, path = '$', found = []) {
  if (typeof value === 'string') {
    if (SECRET_VALUE_PATTERN.test(value)) found.push(path);
    return found;
  }
  if (Array.isArray(value)) {
    value.forEach((item, i) => findSecrets(item, `${path}[${i}]`, found));
    return found;
  }
  if (value && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) {
      if (SECRET_KEY_PATTERN.test(key)) {
        found.push(`${path}.${key}`);
        continue;
      }
      findSecrets(child, `${path}.${key}`, found);
    }
  }
  return found;
}

/** Redaction applied to everything that reaches evidence, bundles, or results (§13.6). */
export function redact(value) {
  if (typeof value === 'string') return SECRET_VALUE_PATTERN.test(value) ? '[redacted]' : value;
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [key, child] of Object.entries(value)) {
      out[key] = SECRET_KEY_PATTERN.test(key) ? '[redacted]' : redact(child);
    }
    return out;
  }
  return value;
}
