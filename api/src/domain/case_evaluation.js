/**
 * Per-case evaluation (§7.3, §7.4) and the attribution rule from §6.6.
 *
 * These functions are pure: normalized observations in, conclusions out. Two
 * runs with the same normalized evidence must produce identical conclusions
 * regardless of ordering, scheduling, or restarts (§16.4).
 */

/**
 * A block counts as candidate-attributable only when the control names the rule
 * and the active candidate digest, and both belong to the candidate we applied.
 * A generic rejection, a transport failure, or an unrelated rule hit does not.
 */
export function attributeBlock({ control, expectedDigest, candidateRuleIds }) {
  if (!control?.observed) return { attributed: false, reason: 'no control decision was observed' };
  if (control.decision !== 'deny') return { attributed: false, reason: 'control did not deny the request' };
  if (!control.attribution_available) {
    return { attributed: false, reason: 'control emitted a generic rejection with no rule or policy attribution' };
  }
  if (control.active_candidate_digest !== expectedDigest) {
    return { attributed: false, reason: `denying rule reports candidate digest ${control.active_candidate_digest ?? 'none'}, expected ${expectedDigest}` };
  }
  if (!candidateRuleIds.includes(control.matched_rule_id)) {
    return { attributed: false, reason: `matched rule "${control.matched_rule_id}" is not part of the applied candidate` };
  }
  return { attributed: true, reason: `blocked by candidate rule "${control.matched_rule_id}"` };
}

/** Map a normalized observation set to the attack-case candidate-absent vocabulary. */
export function classifyAbsentObservation(observation, expectedBehavior) {
  if (!observation) return { value: 'not-run', note: 'baseline trial was not executed' };
  if (observation.error) return { value: 'unobservable', note: observation.error };
  if (observation.control?.decision === 'deny') {
    return {
      value: 'unobservable',
      note: observation.control.attribution_available
        ? `baseline traffic was denied by pre-existing rule "${observation.control.matched_rule_id}"`
        : 'baseline traffic was denied with no attribution, so candidate-absent behavior cannot be established',
      contaminated: true,
    };
  }
  if (!observation.target?.observed) return { value: 'unobservable', note: 'no protected-target receipt was collected' };

  const markers = observation.target.markers ?? [];
  if (expectedBehavior === 'reached-vulnerable-behavior' && markers.includes('vulnerable-behavior')) {
    return { value: 'reached-vulnerable-behavior', note: 'target reported the vulnerable code path was reached' };
  }
  if (expectedBehavior === 'reached-discriminator-target' && markers.includes('discriminator-target')) {
    return { value: 'reached-discriminator-target', note: 'target reported the discriminator endpoint was reached' };
  }
  return {
    value: 'unobservable',
    note: `target was reached but did not report the expected "${expectedBehavior}" marker (markers: ${markers.length ? markers.join(', ') : 'none'})`,
  };
}

export function classifyPresentObservation(observation) {
  if (!observation) return { value: 'not-run', note: 'candidate-present trial was not executed' };
  if (observation.error) return { value: 'unobservable', note: observation.error };
  if (observation.control?.decision === 'deny') return { value: 'blocked', note: 'control denied the request' };
  if (observation.target?.observed) return { value: 'not-blocked', note: 'request reached the protected target' };
  return { value: 'unobservable', note: 'neither a control decision nor a target receipt could be correlated' };
}

/**
 * Attack case conclusion.
 * `blocked-as-required` demands: an attributable candidate-present block AND,
 * where the policy requires baseline confirmation, a demonstrated
 * candidate-absent behavior.
 */
export function concludeAttackCase({ attackCase, absent, present, attribution, requireBaseline, requireAttribution }) {
  const gaps = [];

  if (present.value === 'not-blocked') {
    return { conclusion: 'not-blocked', rationale: present.note, gaps };
  }
  if (present.value === 'unobservable' || present.value === 'not-run') {
    gaps.push({ code: 'candidate-present-observation-missing', detail: present.note });
    return { conclusion: 'undetermined', rationale: present.note, gaps };
  }

  // present.value === 'blocked'
  if (requireAttribution && !attribution.attributed) {
    gaps.push({ code: 'block-not-candidate-attributable', detail: attribution.reason });
    return { conclusion: 'undetermined', rationale: `blocking observed but not attributable: ${attribution.reason}`, gaps };
  }
  if (requireBaseline) {
    if (absent.contaminated) {
      gaps.push({ code: 'baseline-contaminated', detail: absent.note });
      return { conclusion: 'undetermined', rationale: absent.note, gaps };
    }
    if (absent.value !== attackCase.expected_absent_behavior) {
      gaps.push({ code: 'baseline-behavior-not-demonstrated', detail: absent.note });
      return { conclusion: 'undetermined', rationale: absent.note, gaps };
    }
  }
  return { conclusion: 'blocked-as-required', rationale: attribution.reason, gaps };
}

export function concludeBenignCase({ present }) {
  if (present.value === 'permitted') return { conclusion: 'preserved', rationale: 'request was permitted and reached the target as expected', gaps: [] };
  if (present.value === 'blocked') return { conclusion: 'regressed', rationale: 'the candidate blocked a required benign request', gaps: [] };
  if (present.value === 'altered') return { conclusion: 'regressed', rationale: 'the required benign request was altered by the candidate', gaps: [] };
  return {
    conclusion: 'undetermined',
    rationale: present.note,
    gaps: [{ code: 'benign-observation-missing', detail: present.note }],
  };
}

/** Benign observation vocabulary is `permitted | blocked | altered | unobservable | not-run`. */
export function classifyBenignObservation(observation, benignCase) {
  if (!observation) return { value: 'not-run', note: 'benign trial was not executed' };
  if (observation.error) return { value: 'unobservable', note: observation.error };
  if (observation.control?.decision === 'deny') return { value: 'blocked', note: 'control denied a required benign request' };
  if (!observation.target?.observed) return { value: 'unobservable', note: 'no protected-target receipt was collected' };
  if (observation.target.status_code !== 200) {
    return { value: 'altered', note: `target responded ${observation.target.status_code} where the approved expectation is a permitted outcome` };
  }
  return { value: 'permitted', note: `target accepted the request (${observation.target.status_code})`, expected: benignCase.expected_outcome };
}

/** Aggregate proof strength over the required, established attack cases (§7.5). */
export function aggregateProofStrength(requiredCaseConclusions) {
  if (requiredCaseConclusions.length === 0) return 'not-established';
  if (!requiredCaseConclusions.every((c) => c.conclusion === 'blocked-as-required')) return 'not-established';
  const strengths = new Set(requiredCaseConclusions.map((c) => c.proof_strength));
  if (strengths.size === 1) return strengths.has('direct') ? 'direct' : 'indirect';
  return 'mixed';
}
