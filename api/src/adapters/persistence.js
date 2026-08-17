/**
 * State store (§11.1).
 *
 * Split by mutability, exactly as the logical data model prescribes:
 *   - `defense_validation_result` lives in embedded PostgreSQL (see db.js) and
 *     is immutable once written.
 *   - Run lifecycle, audit, and the outbox stay in process: a run is mutable
 *     until terminal and its steps churn on every transition.
 */
import { nowIso, uuid, sha256 } from '../../../lib/digest.js';
import { insertResult, selectResult, selectLedger, selectLedgerStats, selectCaseMetrics } from './db.js';

/**
 * Run lifecycle, audit, and the outbox stay in memory: a run is mutable until
 * terminal (§11.1) and its steps churn on every transition. The authoritative
 * *result* is what must outlive the process, and that lives in PostgreSQL.
 */
const runs = new Map();
const auditEvents = [];
const outbox = [];
const replayIndex = new Map(); // replay_key -> run_id

export function createRun(record) {
  const run = {
    run_id: `dv-run-${uuid()}`,
    created_at: nowIso(),
    updated_at: nowIso(),
    state: 'accepted',
    steps: [],
    ...record,
  };
  runs.set(run.run_id, run);
  if (run.replay_key) replayIndex.set(run.replay_key, run.run_id);
  return run;
}

export function updateRun(runId, patch) {
  const run = runs.get(runId);
  if (!run) return null;
  if (run.frozen) return run; // terminal runs are immutable
  Object.assign(run, patch, { updated_at: nowIso() });
  return run;
}

export function appendStep(runId, step) {
  const run = runs.get(runId);
  if (!run || run.frozen) return null;
  run.steps.push(step);
  run.updated_at = nowIso();
  return step;
}

export function freezeRun(runId) {
  const run = runs.get(runId);
  if (run) run.frozen = true;
  return run;
}

export function getRun(runId) {
  return runs.get(runId) ?? null;
}

export function findRunByReplayKey(key) {
  const runId = replayIndex.get(key);
  return runId ? runs.get(runId) : null;
}

export function listRuns({ terminal_state, limit = 100 } = {}) {
  return [...runs.values()]
    .filter((r) => !terminal_state || r.terminal_state === terminal_state)
    .sort((a, b) => b.created_at.localeCompare(a.created_at))
    .slice(0, limit);
}

export async function putResult(result) {
  const frozen = Object.freeze(structuredClone(result));
  await insertResult(frozen);
  return frozen;
}

export async function getResult(resultId) {
  return selectResult(resultId);
}

export async function listLedger({ terminal_state, limit = 200 } = {}) {
  return selectLedger({ terminalState: terminal_state ?? null, limit });
}

export async function ledgerStats() {
  return selectLedgerStats();
}


/* --------------------------------------------------------------- audit */

export function audit(runId, event, detail = {}) {
  const record = {
    event_id: `audit-${uuid().slice(0, 12)}`,
    run_id: runId,
    event,
    detail,
    recorded_at: nowIso(),
  };
  auditEvents.push(Object.freeze(record));
  return record;
}

export function listAudit(runId) {
  return auditEvents.filter((e) => !runId || e.run_id === runId);
}

/* ------------------------------------------------- transactional outbox */

export function enqueueEvent(event) {
  const record = {
    event_id: `evt-${uuid().slice(0, 12)}`,
    published: false,
    enqueued_at: nowIso(),
    published_at: null,
    payload: event,
  };
  outbox.push(record);
  return record;
}

export function publishPending() {
  const published = [];
  for (const record of outbox) {
    if (record.published) continue;
    record.published = true;
    record.published_at = nowIso();
    published.push(record);
  }
  return published;
}

export function listEvents({ limit = 100 } = {}) {
  return outbox.slice(-limit).reverse();
}

/* --------------------------------------------------- replay identity §12.3 */

export function computeReplayKey({ request, candidate, attackSuite, benignSuite, context, profile, policy, algorithmVersion }) {
  return sha256({
    contract_id: request.contract_id,
    control_candidate_id: candidate.control_candidate_id,
    candidate_digest: candidate.digest,
    translated_candidate_result_id: candidate.translation.translated_candidate_result_id,
    validation_context_id: context.validation_context_id,
    context_configuration_fingerprint: context.control.configuration_fingerprint,
    attack_suite_id: attackSuite.attack_suite_id,
    attack_suite_digest: attackSuite.digest,
    benign_suite_id: benignSuite.benign_suite_id,
    benign_suite_digest: benignSuite.digest,
    validation_profile_id: profile.validation_profile_id,
    profile_version_digest: profile.version_digest,
    validation_policy_id: policy.validation_policy_id,
    policy_version_digest: policy.version_digest,
    algorithm_version: algorithmVersion,
  });
}

export async function metrics() {
  const all = [...runs.values()];
  const [ledger, cases] = await Promise.all([selectLedgerStats(), selectCaseMetrics()]);
  // Cleanup happens after the result is durable, so it is counted from runs.
  const cleanupFailures = all.filter((r) => r.cleanup_record && r.cleanup_record.removed === false && !r.cleanup_record.not_applicable).length;
  return {
    runs_total: all.length,
    terminal_state_distribution: ledger.terminal_state_distribution,
    attack_case_conclusions: { 'blocked-as-required': 0, 'not-blocked': 0, undetermined: 0, ...cases.attack },
    benign_case_conclusions: { preserved: 0, regressed: 0, undetermined: 0, ...cases.benign },
    candidate_apply_failures: cases.applyFailures,
    candidate_cleanup_failures: cleanupFailures,
    outbox_pending: outbox.filter((e) => !e.published).length,
    durable_results: ledger.total,
  };
}
