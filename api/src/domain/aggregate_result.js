/**
 * Deterministic aggregate result engine (§7.6, §8.1).
 *
 * Terminal-state resolution is a fixed ordered rule list. Every rule is
 * evaluated and recorded — including the ones that did not fire — so the
 * precedence decision is inspectable after the fact without a rerun.
 *
 * Reading note on rule ordering
 * -----------------------------
 * §7.6 lists `inconclusive` above `unsafe`, qualified by "unresolved required
 * evidence *that could change candidate judgment*". Two consequences of taking
 * that qualifier literally are encoded here:
 *
 *   - An established required-benign regression is the highest-precedence
 *     supported negative (§2.4, §8.1: `unsafe` governs). No amount of
 *     still-unresolved evidence can turn it into a different verdict, so it is
 *     not masked by `inconclusive`; the unresolved items are retained as
 *     limitations instead.
 *   - Unresolved *attack* evidence alongside an established attack failure
 *     likewise cannot change the verdict — but only once benign evidence,
 *     context, and candidate state are fully resolved, because an unresolved
 *     benign case could still hide a regression that outranks it.
 *
 * Unknown or stale candidate application state (§7.2) blocks every supported
 * candidate judgment, including `unsafe`.
 */

export function resolveAggregate({
  admission,
  contextAssessment,
  malfunction,
  candidateApplication,
  attackCases,
  benignCases,
  requiredCaseIds,
}) {
  const requiredAttack = attackCases.filter((c) => requiredCaseIds.attack.includes(c.case_id));
  const requiredBenign = benignCases.filter((c) => requiredCaseIds.benign.includes(c.case_id));

  const unresolved = [];
  if (contextAssessment?.status === 'undetermined') {
    for (const finding of contextAssessment.findings.filter((f) => f.severity === 'undetermined')) {
      unresolved.push({ scope: 'context', code: finding.code, detail: finding.detail });
    }
  }
  for (const c of requiredAttack.filter((c) => c.conclusion === 'undetermined')) {
    unresolved.push({ scope: 'attack-case', case_id: c.case_id, code: c.gaps[0]?.code ?? 'undetermined', detail: c.rationale });
  }
  for (const c of requiredBenign.filter((c) => c.conclusion === 'undetermined')) {
    unresolved.push({ scope: 'benign-case', case_id: c.case_id, code: c.gaps[0]?.code ?? 'undetermined', detail: c.rationale });
  }

  const benignRegressed = requiredBenign.filter((c) => c.conclusion === 'regressed');
  const attackNotBlocked = requiredAttack.filter((c) => c.conclusion === 'not-blocked');
  const benignFullyResolved = requiredBenign.every((c) => c.conclusion !== 'undetermined') && requiredBenign.length > 0;
  const contextResolved = contextAssessment?.status === 'valid';
  const candidateStateEstablished = Boolean(candidateApplication?.state_established);

  const rules = [
    {
      rule: 1,
      name: 'scope-declined',
      state: 'scope-declined',
      applies: admission && admission.admitted === false,
      because: () => `request is valid but outside configured coverage: ${admission.findings.map((f) => f.code).join(', ')}`,
    },
    {
      rule: 2,
      name: 'environment-invalid',
      state: 'environment-invalid',
      applies: contextAssessment?.status === 'invalid',
      because: () =>
        `validation context fails approved semantics: ${contextAssessment.findings.filter((f) => f.severity === 'invalid').map((f) => f.code).join(', ')}`,
    },
    {
      rule: 3,
      name: 'malfunction',
      state: 'malfunction',
      applies: Boolean(malfunction),
      because: () => `runtime cannot emit a trustworthy domain result: ${malfunction.category}`,
    },
    {
      rule: 4,
      name: 'candidate-state-not-established',
      state: 'inconclusive',
      applies: !candidateStateEstablished,
      because: () =>
        `candidate application state is ${candidateApplication?.state ?? 'unknown'}; no supported candidate judgment can be made (§7.2)`,
    },
    {
      rule: 5,
      name: 'unsafe-governs',
      state: 'unsafe',
      applies: benignRegressed.length > 0,
      because: () =>
        `${benignRegressed.length} required benign case(s) regressed: ${benignRegressed.map((c) => c.case_id).join(', ')}` +
        (attackNotBlocked.length ? `; ${attackNotBlocked.length} attack failure(s) retained` : ''),
    },
    {
      rule: 6,
      name: 'unresolved-required-evidence',
      state: 'inconclusive',
      applies:
        unresolved.length > 0 &&
        !(attackNotBlocked.length > 0 && benignFullyResolved && contextResolved && candidateStateEstablished),
      because: () => `${unresolved.length} required evidence item(s) unresolved: ${unresolved.map((u) => u.code).join(', ')}`,
    },
    {
      rule: 7,
      name: 'failed-to-block',
      state: 'failed-to-block',
      applies: attackNotBlocked.length > 0,
      because: () => `${attackNotBlocked.length} required attack case(s) not blocked: ${attackNotBlocked.map((c) => c.case_id).join(', ')}`,
    },
    {
      rule: 8,
      name: 'validated',
      state: 'validated',
      applies: requiredAttack.length > 0 && requiredBenign.length > 0 && requiredAttack.every((c) => c.conclusion === 'blocked-as-required') && requiredBenign.every((c) => c.conclusion === 'preserved'),
      because: () =>
        `all ${requiredAttack.length} required attack case(s) blocked as required and all ${requiredBenign.length} required benign case(s) preserved in a valid context`,
    },
  ];

  let terminal = null;
  const trace = rules.map((r) => {
    const fired = !terminal && r.applies;
    if (fired) terminal = { state: r.state, rule: r.rule, name: r.name, reason: r.because() };
    return {
      rule: r.rule,
      name: r.name,
      terminal_state: r.state,
      condition_met: Boolean(r.applies),
      fired,
      reason: r.applies ? r.because() : null,
    };
  });

  if (!terminal) {
    // No rule fired: required evidence is complete but does not satisfy any
    // supported judgment. That is itself a result-assembly invariant failure.
    terminal = {
      state: 'inconclusive',
      rule: null,
      name: 'no-rule-satisfied',
      reason: 'required evidence is complete but satisfies no supported candidate judgment',
    };
  }

  return {
    terminal_state: terminal.state,
    decided_by: { rule: terminal.rule, name: terminal.name, reason: terminal.reason },
    precedence_trace: trace,
    unresolved,
    retained_findings: {
      benign_regressions: benignRegressed.map((c) => c.case_id),
      attack_failures: attackNotBlocked.map((c) => c.case_id),
      unresolved_required_evidence: unresolved,
    },
  };
}
