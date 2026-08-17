/**
 * Validation Context Evaluator (§6.3, §7.1).
 *
 * Compares the approved context descriptor *and* live control evidence against
 * the signed profile's requirements. Produces
 *   ContextAssessment { status: valid | invalid | undetermined, findings[] }
 *
 * Distinction that matters: a requirement the context provably violates is
 * `invalid`; a requirement whose evidence is missing or unreadable is
 * `undetermined`, which downstream normally resolves to `inconclusive`.
 */
export function assessContext({ context, profile, probe, probeError }) {
  const findings = [];
  const add = (severity, code, detail) => findings.push({ severity, code, detail });

  /* ---- declared context descriptor vs profile ---- */

  if (!profile.supported_versions.includes(context.control.version)) {
    add('invalid', 'control-version-unsupported', `context control version "${context.control.version}" is not in the profile's approved set [${profile.supported_versions.join(', ')}]`);
  }
  if (context.isolation.environment !== profile.required_isolation.environment) {
    add('invalid', 'isolation-environment-mismatch', `context environment "${context.isolation.environment}" does not satisfy the required "${profile.required_isolation.environment}"`);
  }
  if (profile.required_isolation.reset_supported && !context.isolation.reset_supported) {
    add('invalid', 'reset-unsupported', 'profile requires a resettable context; the descriptor declares reset is unsupported');
  }
  for (const capability of profile.required_observation) {
    if (!context.observation?.[capability]) {
      add('invalid', 'observation-capability-missing', `profile requires "${capability}" observation; the context does not declare it`);
    }
  }
  for (const claim of profile.required_fidelity_claims) {
    if (!context.fidelity?.claims?.includes(claim)) {
      add('invalid', 'fidelity-claim-missing', `profile requires fidelity claim "${claim}"`);
    }
  }
  if (profile.required_fidelity_claims.length > 0 && (context.fidelity?.evidence_refs ?? []).length === 0) {
    add('undetermined', 'fidelity-evidence-absent', 'fidelity claims are declared but no supporting evidence is referenced');
  }

  /* ---- live control evidence vs the approved descriptor ---- */

  if (probeError) {
    add('undetermined', 'context-probe-unavailable', `live control state could not be read: ${probeError}`);
  } else if (probe) {
    if (probe.control.technology !== context.control.technology || probe.control.version !== context.control.version) {
      add('invalid', 'context-identity-mismatch', `live control reports ${probe.control.technology} ${probe.control.version}; the approved descriptor claims ${context.control.technology} ${context.control.version}`);
    }
    if (probe.configuration_fingerprint !== context.control.configuration_fingerprint) {
      add('invalid', 'configuration-fingerprint-mismatch', `live configuration fingerprint ${probe.configuration_fingerprint} differs from the approved ${context.control.configuration_fingerprint}`);
    }
    if (probe.isolation?.environment !== context.isolation.environment) {
      add('invalid', 'isolation-evidence-mismatch', `live control reports environment "${probe.isolation?.environment}"`);
    }
    if (probe.preinstalled_rule_ids?.length) {
      add('note', 'preexisting-control-rules', `context carries ${probe.preinstalled_rule_ids.length} unrelated pre-installed rule(s): ${probe.preinstalled_rule_ids.join(', ')}. Blocking observations must be attributed to the candidate.`);
    }
    if (probe.active_applications?.length) {
      add('invalid', 'residual-candidate-application', `context is not clean: ${probe.active_applications.length} candidate application(s) already active`);
    }
  } else {
    add('undetermined', 'context-probe-absent', 'no live control evidence was collected');
  }

  const status = findings.some((f) => f.severity === 'invalid')
    ? 'invalid'
    : findings.some((f) => f.severity === 'undetermined')
      ? 'undetermined'
      : 'valid';

  return {
    status,
    findings,
    evaluated_against: {
      validation_profile_id: profile.validation_profile_id,
      profile_version_digest: profile.version_digest,
      validation_context_id: context.validation_context_id,
      context_descriptor_digest: context.descriptor_digest,
      observed_configuration_fingerprint: probe?.configuration_fingerprint ?? null,
    },
  };
}
