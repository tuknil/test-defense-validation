/**
 * Admission / coverage evaluation (§5.2 step 6, §7.6 rule 1).
 *
 * Runs before any execution. A valid request that the configured profile does
 * not cover is `scope-declined` — an explicit scope statement, never a defect
 * and never a security finding.
 */
export function evaluateAdmission({ profile, attackSuite, benignSuite, context, policy }) {
  const findings = [];

  if (!profile.supported_control_classes.includes(context.control.class)) {
    findings.push({
      code: 'control-class-unsupported',
      detail: `profile covers control classes [${profile.supported_control_classes.join(', ')}]; context declares "${context.control.class}"`,
    });
  }
  if (!profile.supported_technologies.includes(context.control.technology)) {
    findings.push({
      code: 'control-technology-unsupported',
      detail: `profile covers technologies [${profile.supported_technologies.join(', ')}]; context declares "${context.control.technology}"`,
    });
  }
  for (const suite of [attackSuite, benignSuite]) {
    if (!profile.supported_case_modalities.includes(suite.modality)) {
      findings.push({
        code: 'suite-modality-unsupported',
        detail: `profile supports modalities [${profile.supported_case_modalities.join(', ')}]; suite "${suite.attack_suite_id ?? suite.benign_suite_id}" declares "${suite.modality}"`,
      });
    }
  }
  const proofStrengths = [...new Set(attackSuite.cases.map((c) => c.proof_strength))];
  for (const strength of proofStrengths) {
    if (!profile.supported_proof_strengths.includes(strength)) {
      findings.push({
        code: 'proof-path-unsupported',
        detail: `profile supports proof strengths [${profile.supported_proof_strengths.join(', ')}]; attack suite contains "${strength}" cases`,
      });
    }
  }
  const caseCount = attackSuite.cases.length + benignSuite.cases.length;
  if (caseCount > policy.max_cases_per_run) {
    findings.push({
      code: 'case-budget-exceeded',
      detail: `${caseCount} cases exceeds the policy limit of ${policy.max_cases_per_run}`,
    });
  }

  return { admitted: findings.length === 0, findings };
}

/** Resolve the policy-required case ID sets for a run. */
export function resolveRequiredCases(policy, attackSuite, benignSuite) {
  const pick = (spec, cases) =>
    spec === 'all' ? cases.map((c) => c.case_id) : cases.map((c) => c.case_id).filter((id) => spec.includes(id));
  return {
    attack: pick(policy.required_attack_cases, attackSuite.cases),
    benign: pick(policy.required_benign_cases, benignSuite.cases),
  };
}
