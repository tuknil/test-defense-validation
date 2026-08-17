/**
 * Defense Validation Worker (§5.2, §6.2).
 *
 * Authoritative orchestration. Every numbered step below maps to the LLD's
 * step-by-step processing rules and is recorded on the run so the pipeline is
 * inspectable while it executes and after it completes.
 *
 * The worker never fabricates a domain judgment: adapter and runner failures
 * become explicit observation gaps or a `malfunction`, never an assumed
 * blocked/permitted outcome.
 */
import { nowIso, sha256 } from '../../../lib/digest.js';
import { bindSuppliedInputs } from '../domain/input_binding.js';
import { evaluateAdmission, resolveRequiredCases } from '../domain/admission.js';
import { assessContext } from '../domain/context_evaluator.js';
import {
  attributeBlock,
  classifyAbsentObservation,
  classifyPresentObservation,
  classifyBenignObservation,
  concludeAttackCase,
  concludeBenignCase,
  aggregateProofStrength,
} from '../domain/case_evaluation.js';
import { resolveAggregate } from '../domain/aggregate_result.js';
import { checkResultInvariants } from '../domain/invariants.js';
import { modsecurityControlAdapter, AdapterError } from '../adapters/control/modsecurity.js';
import { localHttpRunner } from '../adapters/runner/local_http.js';
import { safebreachRunner } from '../adapters/runner/safebreach.js';
import { normalizeExecution } from '../adapters/observation_normalizer.js';
import { putEvidence, buildReferenceBundle, attachCleanupAddendum } from '../adapters/evidence.js';
import * as store from '../adapters/persistence.js';
import { ALGORITHM_VERSION, STEP_PACING_MS } from '../config.js';

const RUNNERS = { [localHttpRunner.adapter_id]: localHttpRunner, [safebreachRunner.adapter_id]: safebreachRunner };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const NO_OVERCLAIM_LIMITATIONS = [
  'This result speaks only to the selected validation context. It makes no statement about production safety, deployment authorization, live blast radius, or performance impact.',
  'Blocking is established only for the supplied attack cases. No claim is made about resistance to bypasses outside those cases.',
];

export async function executeRun(runId) {
  const run = store.getRun(runId);
  if (!run) return null;

  const ctx = {
    run,
    steps: [],
    evidenceRefs: [],
    limitations: [],
    malfunction: null,
    candidateApplication: { state: 'not-attempted', state_established: false, applied: false },
    application: null,
    context: null,
  };

  const step = async (seq, name, fn) => {
    const started_at = nowIso();
    const t0 = Date.now();
    const record = { seq, name, status: 'running', started_at, detail: null, ended_at: null, duration_ms: null };
    ctx.steps.push(record);
    store.appendStep(runId, record);
    try {
      const outcome = await fn();
      Object.assign(record, {
        status: outcome?.status ?? 'ok',
        detail: outcome?.detail ?? null,
        ended_at: nowIso(),
        duration_ms: Date.now() - t0,
      });
      if (STEP_PACING_MS) await sleep(STEP_PACING_MS);
      return outcome?.value;
    } catch (err) {
      Object.assign(record, { status: 'failed', detail: err.message, ended_at: nowIso(), duration_ms: Date.now() - t0 });
      throw err;
    }
  };

  const skip = (seq, name, detail) => {
    const record = { seq, name, status: 'skipped', started_at: nowIso(), ended_at: nowIso(), duration_ms: 0, detail };
    ctx.steps.push(record);
    store.appendStep(runId, record);
  };

  const addEvidence = async (kind, payload, claim_type) => {
    const ref = await putEvidence({ kind, payload, claim_type, run_id: runId });
    ctx.evidenceRefs.push(ref);
    return ref;
  };

  store.updateRun(runId, { state: 'queued' });
  store.audit(runId, 'run.dequeued');

  try {
    /* 1. Bind the supplied material and derive its identities. */
    const inputs = await step(1, 'bind-supplied-input-material', () => {
      const bound = bindSuppliedInputs(run.request);
      return {
        value: bound,
        detail: `bound candidate ${bound.candidate.control_candidate_id} and 5 supporting artifacts by derived digest`,
      };
    });
    ctx.context = inputs.context;
    const { candidate, attackSuite, benignSuite, context } = inputs;

    /* 3. Verify candidate digest and translation ancestry. */
    await step(2, 'verify-candidate-digest-and-ancestry', async () => {
      const recomputed = sha256(candidate.artifact);
      if (recomputed !== candidate.digest) {
        throw new AdapterError('artifact-resolution-failure', 'candidate artifact digest does not match the digest derived at binding');
      }
      if (!candidate.translation?.translated_candidate_result_id) {
        throw new AdapterError('artifact-resolution-failure', 'candidate has no translation ancestry');
      }
      await addEvidence('candidate-artifact', { control_candidate_id: candidate.control_candidate_id, digest: candidate.digest, translation: candidate.translation, artifact: candidate.artifact }, 'candidate-applied');
      return { detail: `digest verified ${candidate.digest.slice(0, 20)}…` };
    });

    /* 4. Validate required suite case metadata. */
    await step(3, 'validate-suite-case-metadata', () => {
      for (const c of attackSuite.cases) {
        if (!c.case_id || !c.proof_strength || !c.expected_absent_behavior) {
          throw new AdapterError('artifact-resolution-failure', `attack case ${c.case_id ?? '(unnamed)'} is missing required metadata`);
        }
      }
      for (const c of benignSuite.cases) {
        if (!c.case_id || !c.expected_outcome) throw new AdapterError('artifact-resolution-failure', `benign case ${c.case_id ?? '(unnamed)'} is missing an expected outcome`);
      }
      return { detail: `${attackSuite.cases.length} attack case(s), ${benignSuite.cases.length} benign case(s)` };
    });

    /* 5. Resolve signed profile and policy. */
    const { profile, policy } = await step(4, 'verify-signed-profile-and-policy', () => {
      const { profile, policy } = inputs;
      if (!profile.signature || !policy.signature) throw new AdapterError('invalid-policy-profile', 'unsigned semantic artifact refused');
      return { value: { profile, policy }, detail: `${profile.validation_profile_id} + ${policy.validation_policy_id}` };
    });

    const requiredCaseIds = resolveRequiredCases(policy, attackSuite, benignSuite);

    /* 6. Admission / configured coverage. */
    const admission = await step(5, 'evaluate-configured-coverage', async () => {
      const result = evaluateAdmission({ profile, attackSuite, benignSuite, context, policy });
      await addEvidence('admission-finding', result, result.admitted ? null : 'limitation');
      return { value: result, status: result.admitted ? 'ok' : 'declined', detail: result.admitted ? 'in scope' : result.findings.map((f) => f.code).join(', ') };
    });

    if (!admission.admitted) {
      for (let seq = 6; seq <= 16; seq += 1) skip(seq, STEP_NAMES[seq], 'not reached: request declined before execution');
      return await finalize(ctx, {
        run, candidate, attackSuite, benignSuite, context, profile, policy, requiredCaseIds,
        admission, contextAssessment: null, attackCases: [], benignCases: [],
      });
    }

    /* 7. Resolve context and assess validity BEFORE any candidate judgment. */
    store.updateRun(runId, { state: 'context_check' });
    const contextAssessment = await step(6, 'assess-validation-context', async () => {
      let probe = null;
      let probeError = null;
      try {
        probe = await modsecurityControlAdapter.describeContext(context);
      } catch (err) {
        probeError = err.message;
      }
      const assessment = assessContext({ context, profile, probe, probeError });
      await addEvidence('context-probe', { descriptor: context, live_control_state: probe, probe_error: probeError, assessment }, 'context-valid');
      return {
        value: assessment,
        status: assessment.status === 'valid' ? 'ok' : assessment.status === 'invalid' ? 'failed-domain' : 'undetermined',
        detail: `${assessment.status}${assessment.findings.length ? `: ${assessment.findings.map((f) => f.code).join(', ')}` : ''}`,
      };
    });

    if (contextAssessment.status === 'invalid') {
      for (let seq = 7; seq <= 16; seq += 1) skip(seq, STEP_NAMES[seq], 'not reached: context is invalid, no candidate judgment is permitted');
      return await finalize(ctx, {
        run, candidate, attackSuite, benignSuite, context, profile, policy, requiredCaseIds,
        admission, contextAssessment, attackCases: [], benignCases: [],
      });
    }

    store.updateRun(runId, { state: 'running' });
    const runner = RUNNERS[context.execution.runner_adapter_id];
    if (!runner) throw new AdapterError('runner-failure', `no runner adapter for ${context.execution.runner_adapter_id}`);

    /* 8. Establish candidate-absent state. */
    const baselineState = await step(7, 'establish-candidate-absent-state', async () => {
      const state = await modsecurityControlAdapter.establishBaseline(context);
      await addEvidence('control-state-baseline', state.raw, 'candidate-applied');
      if (!state.state_established) throw new AdapterError('candidate-application-failure', 'context is not in a candidate-absent state before baseline');
      return { value: state, detail: `candidate absent; ${state.active_rule_ids.length} pre-existing rule(s) active` };
    });

    /* 9. Baseline attack trials where the policy requires confirmation. */
    const baselineObservations = new Map();
    if (policy.require_baseline_confirmation) {
      await step(8, 'execute-baseline-attack-trials', async () => {
        for (const attackCase of attackSuite.cases) {
          const observation = await runCase(runner, context, attackCase, 'candidate-absent', [], addEvidence);
          baselineObservations.set(attackCase.case_id, observation);
        }
        const reached = [...baselineObservations.values()].filter((o) => o.target?.reached).length;
        return { detail: `${reached}/${attackSuite.cases.length} case(s) reached the protected target without the candidate` };
      });
    } else {
      skip(8, STEP_NAMES[8], 'policy does not require baseline confirmation');
    }

    /* 10. Apply the exact candidate. */
    const application = await step(9, 'apply-exact-candidate', async () => {
      const applied = await modsecurityControlAdapter.apply(context, candidate);
      ctx.application = applied;
      await addEvidence('candidate-application', applied.raw, 'candidate-applied');
      return { value: applied, detail: `application ${applied.application_id}; rules ${applied.applied_rule_ids.join(', ')}` };
    });

    /* 11. Verify the exact applied artifact identity. */
    const verified = await step(10, 'verify-applied-candidate-state', async () => {
      const state = await modsecurityControlAdapter.verifyApplied(context, application, candidate.digest);
      await addEvidence('control-state-verified', state.raw, 'candidate-applied');
      ctx.candidateApplication = {
        applied: true,
        state: state.state,
        state_established: state.state_established,
        application_id: application.application_id,
        applied_candidate_digest: candidate.digest,
        active_candidate_digests: state.active_candidate_digests,
        applied_rule_ids: application.applied_rule_ids,
        applied_at: application.applied_at,
      };
      return { value: state, status: state.state_established ? 'ok' : 'undetermined', detail: state.state };
    });

    /* 12. Candidate-present attack trials. */
    const presentAttack = new Map();
    await step(11, 'execute-candidate-present-attack-suite', async () => {
      for (const attackCase of attackSuite.cases) {
        presentAttack.set(attackCase.case_id, await runCase(runner, context, attackCase, 'candidate-present', [application.application_id], addEvidence));
      }
      const denied = [...presentAttack.values()].filter((o) => o.control?.decision === 'deny').length;
      return { detail: `${denied}/${attackSuite.cases.length} case(s) denied by the control` };
    });

    /* 13. Candidate-present benign trials. */
    const presentBenign = new Map();
    await step(12, 'execute-candidate-present-benign-suite', async () => {
      for (const benignCase of benignSuite.cases) {
        presentBenign.set(benignCase.case_id, await runCase(runner, context, benignCase, 'candidate-present', [application.application_id], addEvidence));
      }
      const permitted = [...presentBenign.values()].filter((o) => o.target?.reached).length;
      return { detail: `${permitted}/${benignSuite.cases.length} benign case(s) permitted` };
    });

    /* 14. Correlate and conclude cases. */
    const candidateRuleIds = candidate.artifact.rules.map((r) => r.rule_id);
    const attackCases = await step(13, 'resolve-attack-case-conclusions', () => {
      const rows = attackSuite.cases.map((attackCase) => {
        const absentObs = baselineObservations.get(attackCase.case_id) ?? null;
        const presentObs = presentAttack.get(attackCase.case_id) ?? null;
        const absent = classifyAbsentObservation(absentObs, attackCase.expected_absent_behavior);
        const present = classifyPresentObservation(presentObs);
        const attribution = attributeBlock({ control: presentObs?.control, expectedDigest: candidate.digest, candidateRuleIds });
        const { conclusion, rationale, gaps } = concludeAttackCase({
          attackCase,
          absent,
          present,
          attribution,
          requireBaseline: policy.require_baseline_confirmation,
          requireAttribution: policy.require_candidate_attribution && profile.requires_candidate_attribution,
        });
        return {
          case_id: attackCase.case_id,
          required: requiredCaseIds.attack.includes(attackCase.case_id),
          proof_strength: attackCase.proof_strength,
          provenance: attackCase.provenance,
          expected_absent_behavior: attackCase.expected_absent_behavior,
          candidate_absent_observation: absent.value,
          candidate_absent_note: absent.note,
          candidate_present_observation: present.value,
          candidate_present_note: present.note,
          attribution: { attributed: attribution.attributed, reason: attribution.reason },
          conclusion,
          rationale,
          gaps,
          evidence_refs: [absentObs?.evidence_ref, presentObs?.evidence_ref].filter(Boolean),
        };
      });
      return { value: rows, detail: summarize(rows.map((r) => r.conclusion)) };
    });

    const benignCases = await step(14, 'resolve-benign-case-conclusions', () => {
      const rows = benignSuite.cases.map((benignCase) => {
        const observation = presentBenign.get(benignCase.case_id) ?? null;
        const present = classifyBenignObservation(observation, benignCase);
        const { conclusion, rationale, gaps } = concludeBenignCase({ present });
        return {
          case_id: benignCase.case_id,
          required: requiredCaseIds.benign.includes(benignCase.case_id),
          expected_outcome: benignCase.expected_outcome,
          candidate_present_observation: present.value,
          candidate_present_note: present.note,
          conclusion,
          rationale,
          gaps,
          evidence_refs: [observation?.evidence_ref].filter(Boolean),
        };
      });
      return { value: rows, detail: summarize(rows.map((r) => r.conclusion)) };
    });

    return await finalize(ctx, {
      run, candidate, attackSuite, benignSuite, context, profile, policy, requiredCaseIds,
      admission, contextAssessment, attackCases, benignCases, verified, baselineState,
    });
  } catch (err) {
    // Any escape from the orchestration means no trustworthy domain result.
    ctx.malfunction = {
      category: err.category ?? 'result-assembly-failure',
      message: err.message,
      candidate_state_known: err.stateKnown !== false,
      occurred_at: nowIso(),
    };
    if (err.stateKnown === false) {
      ctx.candidateApplication = { applied: 'unknown', state: 'unknown', state_established: false, apply_failed: true };
    }
    store.audit(runId, 'run.malfunction', ctx.malfunction);
    const inputs = safeInputs(run);
    return await finalize(ctx, {
      run,
      ...inputs,
      requiredCaseIds: { attack: [], benign: [] },
      admission: { admitted: true, findings: [] },
      contextAssessment: null,
      attackCases: [],
      benignCases: [],
    });
  } finally {
    /* 16. Remove/reset the candidate and capture cleanup evidence — always, and
       always after the authoritative result is durable (§5.2). The run is
       frozen only once this has been recorded. */
    await cleanup(ctx, runId);
    store.freezeRun(runId);
  }
}

const STEP_NAMES = {
  1: 'bind-supplied-input-material',
  2: 'verify-candidate-digest-and-ancestry',
  3: 'validate-suite-case-metadata',
  4: 'verify-signed-profile-and-policy',
  5: 'evaluate-configured-coverage',
  6: 'assess-validation-context',
  7: 'establish-candidate-absent-state',
  8: 'execute-baseline-attack-trials',
  9: 'apply-exact-candidate',
  10: 'verify-applied-candidate-state',
  11: 'execute-candidate-present-attack-suite',
  12: 'execute-candidate-present-benign-suite',
  13: 'resolve-attack-case-conclusions',
  14: 'resolve-benign-case-conclusions',
  15: 'resolve-terminal-state',
  16: 'persist-result-bundle-and-outbox',
};

/**
 * Best-effort binding for the malfunction path, where the failure may itself be
 * a binding failure. A result must still name what it was about.
 */
function safeInputs(run) {
  try {
    return bindSuppliedInputs(run.request);
  } catch {
    return { candidate: null, attackSuite: null, benignSuite: null, context: null, profile: null, policy: null };
  }
}

function summarize(values) {
  const counts = values.reduce((acc, v) => ({ ...acc, [v]: (acc[v] ?? 0) + 1 }), {});
  return Object.entries(counts).map(([k, v]) => `${v} ${k}`).join(', ');
}

/** Execute one case in one trial, normalize it, and store its evidence. */
async function runCase(runner, context, testCase, trial, expectedApplicationIds, addEvidence) {
  let execution;
  try {
    execution = await runner.execute(context, testCase, trial);
  } catch (err) {
    // A runner failure is an observation gap, not a domain verdict (§12.1).
    const failed = { case_id: testCase.case_id, trial, runner: runner.adapter_id, error: `runner failure: ${err.message}` };
    failed.evidence_ref = (await addEvidence('case-execution-failure', failed, 'limitation')).evidence_ref;
    return failed;
  }
  const observation = normalizeExecution(execution, { caseId: testCase.case_id, trial, expectedApplicationIds });
  const ref = await addEvidence('case-execution', { request: testCase.request, execution, normalized: observation }, trial === 'candidate-absent' ? 'limitation' : 'attack-blocked');
  observation.evidence_ref = ref.evidence_ref;
  return observation;
}

async function cleanup(ctx, runId) {
  const record = async (status, detail, cleanupRecord, duration = 0) => {
    const step = { seq: 17, name: 'remove-or-reset-candidate', status, detail, started_at: nowIso(), ended_at: nowIso(), duration_ms: duration };
    ctx.steps.push(step);
    store.appendStep(runId, step);
    ctx.cleanup = cleanupRecord;
    store.updateRun(runId, { cleanup_record: cleanupRecord });
    if (ctx.resultId) await attachCleanupAddendum(ctx.resultId, cleanupRecord);
  };

  if (ctx.candidateApplication?.apply_failed || (ctx.candidateApplication?.state === 'unknown' && !ctx.application)) {
    // §12.2: never blindly reapply or remove when the prior apply outcome is
    // unknown — the state has to be reconciled by an operator first.
    const detail = 'candidate application state is unknown; automatic removal was withheld pending operator reconciliation';
    await record('reconciliation-required', detail, { removed: false, reconciliation_required: true, detail });
    store.audit(runId, 'candidate.cleanup.withheld', { detail });
    return;
  }
  if (!ctx.application) {
    await record('skipped', 'no candidate was applied in this run, so nothing required removal', { removed: false, not_applicable: true });
    return;
  }

  const t0 = Date.now();
  let outcome;
  try {
    outcome = await modsecurityControlAdapter.removeOrReset(ctx.context, ctx.application);
  } catch (err) {
    outcome = { removed: false, error: err.message };
  }
  const ref = await putEvidence({ kind: 'candidate-reset', payload: outcome, claim_type: 'candidate-applied', run_id: runId });
  ctx.evidenceRefs.push(ref);
  const cleanupRecord = { ...outcome, evidence_ref: ref.evidence_ref };
  await record(
    outcome.removed ? 'ok' : 'failed',
    outcome.removed ? `application ${ctx.application.application_id} removed; context reset` : outcome.error,
    cleanupRecord,
    Date.now() - t0,
  );
  store.audit(runId, outcome.removed ? 'candidate.removed' : 'candidate.cleanup.failed', cleanupRecord);
}

/* ------------------------------------------------------ result assembly */

async function finalize(ctx, args) {
  const { run, candidate, attackSuite, benignSuite, context, profile, policy, requiredCaseIds, admission, contextAssessment, attackCases, benignCases } = args;
  const runId = run.run_id;

  const aggregate = resolveAggregate({
    admission,
    contextAssessment,
    malfunction: ctx.malfunction,
    candidateApplication: ctx.candidateApplication,
    attackCases,
    benignCases,
    requiredCaseIds,
  });
  ctx.steps.push({ seq: 15, name: STEP_NAMES[15], status: 'ok', detail: `${aggregate.terminal_state} (rule ${aggregate.decided_by.rule ?? '—'}: ${aggregate.decided_by.name})`, started_at: nowIso(), ended_at: nowIso(), duration_ms: 0 });
  store.appendStep(runId, ctx.steps.at(-1));

  const requiredAttack = attackCases.filter((c) => c.required);
  const proofStrength = aggregate.terminal_state === 'validated' ? aggregateProofStrength(requiredAttack) : aggregateProofStrength(requiredAttack) === 'not-established' ? 'not-established' : aggregateProofStrength(requiredAttack);

  const limitations = buildLimitations({ ctx, aggregate, attackSuite, benignSuite, context, contextAssessment, requiredAttack, policy, profile });
  const evidenceBindings = buildEvidenceBindings({ ctx, contextAssessment, attackCases, benignCases });

  const result = {
    contract_id: 'defense-validation@1.0',
    result_id: run.result_id,
    run_id: runId,
    produced_at: nowIso(),
    algorithm_version: ALGORITHM_VERSION,
    subject: {
      vulnerability_id: candidate?.vulnerability_id ?? null,
      control_candidate_id: candidate?.control_candidate_id ?? run.input_summary?.control_candidate_id ?? null,
      candidate_digest: candidate?.digest ?? null,
      target_control_class: candidate?.target_control_class ?? null,
      target_technology: candidate?.target_technology ?? null,
    },
    input_bindings: {
      translated_candidate_result_id: candidate?.translation?.translated_candidate_result_id ?? null,
      validation_context_id: context?.validation_context_id ?? run.input_summary?.validation_context_id ?? null,
      context_configuration_fingerprint: context?.control?.configuration_fingerprint ?? null,
      attack_suite_id: attackSuite?.attack_suite_id ?? run.input_summary?.attack_suite_id ?? null,
      attack_suite_digest: attackSuite?.digest ?? null,
      benign_suite_id: benignSuite?.benign_suite_id ?? run.input_summary?.benign_suite_id ?? null,
      benign_suite_digest: benignSuite?.digest ?? null,
      validation_profile_id: profile?.validation_profile_id ?? run.input_summary?.validation_profile_id ?? null,
      profile_version_digest: profile?.version_digest ?? null,
      validation_policy_id: policy?.validation_policy_id ?? run.input_summary?.validation_policy_id ?? null,
      policy_version_digest: policy?.version_digest ?? null,
      replay_key: run.replay_key,
    },
    terminal_state: aggregate.terminal_state,
    decided_by: aggregate.decided_by,
    precedence_trace: aggregate.precedence_trace,
    proof_strength: proofStrength,
    admission: admission ?? null,
    context_assessment: contextAssessment ?? { status: 'not-assessed', findings: [] },
    candidate_application: {
      ...ctx.candidateApplication,
      // Removal happens after this result is durable, so it is reported on the
      // run and in the reference-bundle addendum rather than inside the result.
      cleanup: { status: 'pending-post-result', note: 'Candidate removal/reset is performed and evidenced after the authoritative result is made durable (§5.2 step 16).' },
      application_evidence_refs: ctx.evidenceRefs.filter((r) => r.kind === 'candidate-application' || r.kind === 'control-state-verified').map((r) => r.evidence_ref),
      removal_or_reset_evidence_refs: ctx.evidenceRefs.filter((r) => r.kind === 'candidate-reset').map((r) => r.evidence_ref),
    },
    required_cases: requiredCaseIds,
    attack_observations: attackCases,
    benign_observations: benignCases,
    retained_findings: aggregate.retained_findings,
    limitations,
    evidence_bindings: evidenceBindings,
    diagnostics: ctx.malfunction ? { category: ctx.malfunction.category, message: ctx.malfunction.message, candidate_state_known: ctx.malfunction.candidate_state_known } : null,
    retention: { policy_id: policy?.validation_policy_id ?? null, retain_days: policy?.retention_days ?? null },
  };

  // Malfunction results carry diagnostics only — never a domain conclusion.
  if (result.terminal_state === 'malfunction') {
    result.attack_observations = attackCases;
    result.benign_observations = benignCases;
    result.proof_strength = 'not-established';
  }

  result.prose_summary = renderProse(result);

  const invariants = checkResultInvariants(result);
  if (!invariants.ok) {
    result.terminal_state = 'malfunction';
    result.proof_strength = 'not-established';
    result.diagnostics = { category: 'result-assembly-failure', message: 'result invariant check failed', violations: invariants.violations };
    result.prose_summary = 'The runtime could not emit a trustworthy domain result for this run. Diagnostics only; no candidate conclusion is stated.';
    store.audit(runId, 'result.invariant-violation', { violations: invariants.violations });
  }
  result.invariant_check = invariants;

  const stored = await store.putResult(result);
  ctx.resultId = stored.result_id;
  const bundle = await buildReferenceBundle(stored, {
    evidenceRefs: ctx.evidenceRefs,
    runSteps: ctx.steps,
    auditEvents: store.listAudit(runId),
  });

  store.updateRun(runId, {
    state: stored.terminal_state,
    terminal_state: stored.terminal_state,
    proof_strength: stored.proof_strength,
    completed_at: nowIso(),
    reference_bundle_digest: bundle.bundle_digest,
  });

  store.enqueueEvent({
    event_type: 'janus.defense-validation.completed.v1',
    run_id: runId,
    result_id: stored.result_id,
    terminal_state: stored.terminal_state,
    proof_strength: stored.proof_strength,
    produced_at: stored.produced_at,
    trace_id: run.trace_id,
  });
  store.publishPending();
  store.audit(runId, 'run.completed', { terminal_state: stored.terminal_state, proof_strength: stored.proof_strength });

  ctx.steps.push({ seq: 16, name: STEP_NAMES[16], status: 'ok', detail: `result ${stored.result_id} and reference bundle persisted; completion event published`, started_at: nowIso(), ended_at: nowIso(), duration_ms: 0 });
  store.appendStep(runId, ctx.steps.at(-1));

  return stored;
}

function buildLimitations({ ctx, aggregate, attackSuite, benignSuite, context, contextAssessment, requiredAttack, policy, profile }) {
  const limitations = [];
  const push = (code, statement) => limitations.push({ code, statement });

  for (const s of NO_OVERCLAIM_LIMITATIONS) push('capability-boundary', s);

  if (requiredAttack.some((c) => c.proof_strength === 'indirect')) {
    push('indirect-proof', 'One or more required attack cases rely on a discriminator target rather than the vulnerable code path. Blocking is established for the discriminator behavior only.');
  }
  for (const limit of attackSuite?.representativeness_limits ?? []) push('attack-suite-representativeness', limit);
  for (const limit of benignSuite?.representativeness_limits ?? []) push('benign-suite-representativeness', limit);
  push('benign-representativeness', 'No-harm evidence extends only to the supplied representative benign cases.');
  for (const limit of context?.limitations ?? []) push('context-limitation', limit);
  for (const finding of contextAssessment?.findings ?? []) {
    if (finding.severity === 'note') push('context-note', finding.detail);
    if (finding.severity === 'undetermined') push('context-evidence-gap', finding.detail);
  }
  for (const item of aggregate.unresolved) {
    push('unresolved-required-evidence', `${item.scope}${item.case_id ? ` ${item.case_id}` : ''}: ${item.detail}`);
  }
  if (policy && policy.required_attack_cases !== 'all') {
    push('partial-required-set', 'The policy designated only a subset of the attack suite as required; the remaining cases were observed but are non-authoritative.');
  }
  if (!policy?.require_baseline_confirmation) {
    push('no-baseline-confirmation', 'The policy did not require candidate-absent baseline confirmation, so candidate-absent behavior was not demonstrated in this run.');
  }
  push('post-result-cleanup', 'Candidate removal and context reset are performed after this result is durable; their evidence is in the reference-bundle addendum, not in this result.');
  if (profile) push('profile-bound', `Semantics are bound to profile ${profile.validation_profile_id}; nothing here transfers to another profile or control technology.`);
  return limitations;
}

function buildEvidenceBindings({ ctx, contextAssessment, attackCases, benignCases }) {
  const bindings = [];
  const refsOfKind = (...kinds) => ctx.evidenceRefs.filter((r) => kinds.includes(r.kind)).map((r) => r.evidence_ref);

  if (contextAssessment) {
    bindings.push({
      claim_type: 'context-valid',
      claim: `validation context assessed "${contextAssessment.status}"`,
      evidence_refs: refsOfKind('context-probe'),
    });
  }
  bindings.push({
    claim_type: 'candidate-applied',
    claim: ctx.candidateApplication.state_established ? 'exact candidate digest verified active on the control' : `candidate application state: ${ctx.candidateApplication.state}`,
    evidence_refs: refsOfKind('candidate-artifact', 'candidate-application', 'control-state-baseline', 'control-state-verified', 'candidate-reset'),
  });
  for (const c of attackCases) {
    bindings.push({
      claim_type: c.conclusion === 'blocked-as-required' ? 'attack-blocked' : 'limitation',
      claim: `attack case ${c.case_id}: ${c.conclusion}`,
      evidence_refs: c.evidence_refs,
    });
  }
  for (const c of benignCases) {
    bindings.push({
      claim_type: c.conclusion === 'preserved' ? 'benign-preserved' : 'limitation',
      claim: `benign case ${c.case_id}: ${c.conclusion}`,
      evidence_refs: c.evidence_refs,
    });
  }
  return bindings;
}

/**
 * Non-authoritative prose rendered from structured fields only (§6.8).
 * It restates what the record already says and adds no domain conclusion.
 */
function renderProse(result) {
  const subject = result.subject.control_candidate_id;
  const contextId = result.input_bindings.validation_context_id;
  const attack = result.attack_observations.filter((o) => o.required);
  const benign = result.benign_observations.filter((o) => o.required);
  const blocked = attack.filter((o) => o.conclusion === 'blocked-as-required').length;
  const preserved = benign.filter((o) => o.conclusion === 'preserved').length;

  switch (result.terminal_state) {
    case 'validated':
      return `Candidate ${subject} was applied to ${contextId} and verified by digest. All ${attack.length} required attack case(s) were blocked with candidate-attributable evidence (${result.proof_strength} proof) and all ${benign.length} required benign case(s) were preserved. This is validation-context evidence only; separate production-safety consideration still applies.`;
    case 'failed-to-block':
      return `Candidate ${subject} was applied to ${contextId}, but ${attack.length - blocked} of ${attack.length} required attack case(s) still reached the protected target. ${preserved} of ${benign.length} required benign case(s) were preserved. The candidate needs correction or rejection.`;
    case 'unsafe':
      return `Candidate ${subject} regressed ${benign.length - preserved} of ${benign.length} required benign case(s) in ${contextId}. Attack findings are retained alongside the regression. The candidate needs correction or rejection.`;
    case 'environment-invalid':
      return `The validation context ${contextId} does not meet the approved profile requirements (${result.context_assessment.findings.filter((f) => f.severity === 'invalid').map((f) => f.code).join(', ')}). No efficacy or no-harm judgment was made about the candidate. The context owner should repair the context.`;
    case 'inconclusive':
      return `Required evidence for candidate ${subject} in ${contextId} could not be resolved: ${result.retained_findings.unresolved_required_evidence.map((u) => u.code).join(', ') || 'see gaps'}. No statement is made about whether the candidate works, fails, or is harmful. Evidence repair or manual review is required.`;
    case 'scope-declined':
      return `The request is well-formed but outside the configured scope of profile ${result.input_bindings.validation_profile_id} (${result.admission?.findings.map((f) => f.code).join(', ')}). This is a scope statement, not a defect or a negative finding. A supported profile or version is required.`;
    default:
      return 'The runtime could not emit a trustworthy domain result for this run. Diagnostics only; no candidate conclusion is stated.';
  }
}
