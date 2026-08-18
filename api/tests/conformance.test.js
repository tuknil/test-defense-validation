/**
 * CFS conformance suite (§16.2) plus the security and determinism tests from
 * §16.3–16.4. Boots the simulator and the API in-process and drives them over
 * real HTTP, so adapters, normalization, and the result engine are all covered.
 */
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';

const SIM_PORT = 8399;
const API_PORT = 8388;
process.env.SIM_PORT = String(SIM_PORT);
process.env.API_PORT = String(API_PORT);
process.env.SIM_BASE_URL = `http://localhost:${SIM_PORT}`;
process.env.STEP_PACING_MS = '0';
process.env.SIM_LATENCY_MS = '10';
// Isolated ledger per test run, so assertions never depend on prior state.
process.env.DATA_DIR = new URL('./.tmp-data/', import.meta.url).pathname;

const API = `http://localhost:${API_PORT}`;
const TOKEN = 'dev-submitter-token';
let servers = [];

before(async () => {
  const { rmSync } = await import('node:fs');
  rmSync(process.env.DATA_DIR, { recursive: true, force: true });
  const { createApp } = await import('../../lib/microhttp.js');
  const simModule = await import('../../sim/server.js');
  const { initDatabase } = await import('../src/adapters/db.js');
  const { registerRoutes } = await import('../src/http/routes.js');
  await initDatabase();
  const api = createApp({ name: 'api-test' });
  registerRoutes(api);
  servers.push(await api.listen(API_PORT));
  servers.push(simModule.server);
});

after(async () => {
  // Close everything holding the loop open, rather than forcing exit(0) —
  // a forced success code would hide a failing suite.
  for (const server of servers) server.close();
  const { closeDatabase } = await import('../src/adapters/db.js');
  await closeDatabase();
});

async function call(path, init = {}) {
  const response = await fetch(`${API}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${TOKEN}`, ...(init.headers ?? {}) },
  });
  return { status: response.status, body: await response.json() };
}

async function runToCompletion(request) {
  const submit = await call('/v1/defense-validation-runs?force=true', { method: 'POST', body: JSON.stringify(request) });
  assert.equal(submit.status, 202, `submit failed: ${JSON.stringify(submit.body)}`);
  const { run_id, result_id } = submit.body;

  // Wait for `finalized`, not just `terminal_state`: the verdict is durable
  // first, but candidate removal and its evidence land afterwards (§5.2 step 16).
  for (let i = 0; i < 200; i += 1) {
    const status = await call(`/v1/defense-validation-runs/${run_id}`);
    if (status.body.finalized) {
      const result = await call(`/v1/defense-validation-results/${result_id}`);
      return { run: status.body, result: result.body };
    }
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`run ${run_id} did not reach a terminal state`);
}

async function scenario(id) {
  const { body } = await call('/v1/example-payloads');
  const found = body.examples.find((e) => e.id === id);
  assert.ok(found, `unknown example ${id}`);
  // Deep-cloned so a test that mutates a payload cannot affect another test.
  return structuredClone(found);
}

/* ------------------------------------------------- CFS conformance §16.2 */

test('CONF-01: direct proof, attacks blocked, benign preserved => validated/direct', async () => {
  const { request } = await scenario('CONF-01');
  const { result } = await runToCompletion(request);

  assert.equal(result.terminal_state, 'validated');
  assert.equal(result.proof_strength, 'direct');
  assert.equal(result.context_assessment.status, 'valid');
  assert.equal(result.candidate_application.state_established, true);

  // Every required attack case demonstrated baseline behavior AND an
  // attributable candidate-present block.
  for (const observation of result.attack_observations.filter((o) => o.required)) {
    assert.equal(observation.conclusion, 'blocked-as-required');
    assert.equal(observation.candidate_absent_observation, 'reached-vulnerable-behavior');
    assert.equal(observation.candidate_present_observation, 'blocked');
    assert.equal(observation.attribution.attributed, true);
  }
  for (const observation of result.benign_observations.filter((o) => o.required)) {
    assert.equal(observation.conclusion, 'preserved');
  }
  // AC-1: bound to the exact candidate that was actually applied.
  assert.equal(result.candidate_application.applied_candidate_digest, result.subject.candidate_digest);
  assert.ok(result.candidate_application.active_candidate_digests.includes(result.subject.candidate_digest));
});

test('CONF-02: discriminator-backed cases => validated/indirect with an explicit limitation', async () => {
  const { request } = await scenario('CONF-02');
  const { result } = await runToCompletion(request);

  assert.equal(result.terminal_state, 'validated');
  assert.equal(result.proof_strength, 'indirect');
  for (const observation of result.attack_observations) {
    assert.equal(observation.candidate_absent_observation, 'reached-discriminator-target');
  }
  assert.ok(result.limitations.some((l) => l.code === 'indirect-proof'));
});

test('CONF-03: a required attack still reaches the target => failed-to-block', async () => {
  const { request } = await scenario('CONF-03');
  const { result } = await runToCompletion(request);

  assert.equal(result.terminal_state, 'failed-to-block');
  const notBlocked = result.attack_observations.filter((o) => o.conclusion === 'not-blocked');
  assert.ok(notBlocked.length >= 1);
  // The benign side must still be complete and preserved for this state.
  assert.ok(result.benign_observations.filter((o) => o.required).every((o) => o.conclusion === 'preserved'));
});

test('CONF-04: benign regression governs over attack failure, both retained', async () => {
  const { request } = await scenario('CONF-04');
  const { result } = await runToCompletion(request);

  assert.equal(result.terminal_state, 'unsafe');
  assert.ok(result.retained_findings.benign_regressions.length >= 1);
  // AC-10: the coexisting attack failure is retained, not overwritten.
  assert.ok(result.retained_findings.attack_failures.length >= 1, 'attack failures must be retained alongside the regression');
  assert.ok(result.attack_observations.length > 0);
});

test('CONF-05: unsupported control version => environment-invalid, no candidate judgment', async () => {
  const { request } = await scenario('CONF-05');
  const { result } = await runToCompletion(request);

  assert.equal(result.terminal_state, 'environment-invalid');
  assert.equal(result.context_assessment.status, 'invalid');
  assert.ok(result.context_assessment.findings.some((f) => f.code === 'control-version-unsupported'));
  // AC-3: no efficacy or no-harm judgment was formed.
  assert.equal(result.attack_observations.length, 0);
  assert.equal(result.benign_observations.length, 0);
  assert.equal(result.candidate_application.applied, false);
});

test('CONF-05b: live configuration fingerprint drift => environment-invalid', async () => {
  const { request } = await scenario('CONF-05b');
  const { result } = await runToCompletion(request);

  assert.equal(result.terminal_state, 'environment-invalid');
  assert.ok(result.context_assessment.findings.some((f) => f.code === 'configuration-fingerprint-mismatch'));
});

test('CONF-06: generic rejection with no attribution => inconclusive', async () => {
  const { request } = await scenario('CONF-06');
  const { result } = await runToCompletion(request);

  assert.equal(result.terminal_state, 'inconclusive');
  const undetermined = result.attack_observations.filter((o) => o.conclusion === 'undetermined');
  assert.ok(undetermined.length >= 1);
  // AC-11: a generic block cannot establish blocking.
  assert.ok(undetermined.every((o) => o.candidate_present_observation === 'blocked'));
  assert.ok(undetermined.some((o) => o.gaps.some((g) => g.code === 'block-not-candidate-attributable')));
});

test('CONF-07: unsupported suite modality => scope-declined before execution', async () => {
  const { request } = await scenario('CONF-07');
  const { result } = await runToCompletion(request);

  assert.equal(result.terminal_state, 'scope-declined');
  assert.ok(result.admission.findings.some((f) => f.code === 'suite-modality-unsupported'));
  assert.equal(result.candidate_application.applied, false);
});

test('CONF-07b: unsupported proof path => scope-declined', async () => {
  const { request } = await scenario('CONF-07b');
  const { result } = await runToCompletion(request);

  assert.equal(result.terminal_state, 'scope-declined');
  assert.ok(result.admission.findings.some((f) => f.code === 'proof-path-unsupported'));
});

test('CONF-08: apply fails with unknown state => malfunction, diagnostics only', async () => {
  const { request } = await scenario('CONF-08');
  const { result } = await runToCompletion(request);

  assert.equal(result.terminal_state, 'malfunction');
  assert.equal(result.diagnostics.category, 'candidate-application-failure');
  assert.equal(result.diagnostics.candidate_state_known, false);
  assert.equal(result.proof_strength, 'not-established');
  // No domain conclusion may be inferred from a malfunction.
  assert.equal(result.attack_observations.length, 0);
  assert.equal(result.benign_observations.length, 0);
});

test('CONF-09: same block with and without the candidate => inconclusive', async () => {
  const { request } = await scenario('CONF-09');
  const { result } = await runToCompletion(request);

  assert.equal(result.terminal_state, 'inconclusive');
  const undetermined = result.attack_observations.filter((o) => o.conclusion === 'undetermined');
  assert.ok(undetermined.length >= 1);
  assert.ok(undetermined.every((o) => o.candidate_absent_observation === 'unobservable'));
});

/* --------------------------------------------------- acceptance criteria */

test('AC-5: removing a required attack observation prevents validated', async () => {
  const { checkResultInvariants } = await import('../src/domain/invariants.js');
  const { request } = await scenario('CONF-01');
  const { result } = await runToCompletion(request);

  const stripped = structuredClone(result);
  stripped.attack_observations = stripped.attack_observations.slice(1);
  stripped.attack_observations[0].conclusion = 'undetermined';
  const check = checkResultInvariants(stripped);
  assert.equal(check.ok, false);
  assert.ok(check.violations.some((v) => v.code === 'validated-with-unblocked-attack'));
});

test('AC-6: removing all required benign observations prevents validated', async () => {
  const { checkResultInvariants } = await import('../src/domain/invariants.js');
  const { request } = await scenario('CONF-01');
  const { result } = await runToCompletion(request);

  const stripped = structuredClone(result);
  stripped.benign_observations = [];
  const check = checkResultInvariants(stripped);
  assert.equal(check.ok, false);
  assert.ok(check.violations.some((v) => v.code === 'validated-without-benign-evidence'));
});

test('AC-13: no secret material reaches the result, prose, or reference bundle', async () => {
  const { findSecrets } = await import('../src/domain/invariants.js');
  const { request } = await scenario('CONF-01');
  const { result } = await runToCompletion(request);

  assert.deepEqual(findSecrets(result), [], 'result contains secret-shaped material');
  const bundle = await call(`/v1/defense-validation-results/${result.result_id}/reference-bundle`);
  assert.deepEqual(findSecrets(bundle.body), [], 'reference bundle contains secret-shaped material');

  // The simulator really does emit a credential, so redaction is doing work.
  const sim = await fetch(`${process.env.SIM_BASE_URL}/waf/v1/instances/waf-payments-dev/transactions`);
  const { transactions } = await sim.json();
  assert.ok(transactions.some((t) => typeof t.simulator_api_key === 'string' && t.simulator_api_key.startsWith('sk-')));
});

test('AC-12: prose and result make no production-safety or coverage claim', async () => {
  for (const id of ['CONF-01', 'CONF-03', 'CONF-04']) {
    const { request } = await scenario(id);
    const { result } = await runToCompletion(request);
    assert.equal(result.invariant_check.ok, true, `invariants failed for ${id}: ${JSON.stringify(result.invariant_check.violations)}`);
    assert.ok(result.limitations.some((l) => l.code === 'capability-boundary'));
  }
});

test('AC-12: the overclaim guard still rejects an affirmative claim', async () => {
  const { checkResultInvariants } = await import('../src/domain/invariants.js');
  const { request } = await scenario('CONF-01');
  const { result } = await runToCompletion(request);

  for (const claim of [
    'The candidate is production-safe and approved for deployment.',
    'This rule provides complete protection against the vulnerability.',
    'The candidate is bypass-resistant across the estate.',
    'Coverage was established for the protected population.',
  ]) {
    const tampered = { ...structuredClone(result), prose_summary: claim };
    const check = checkResultInvariants(tampered);
    assert.equal(check.ok, false, `overclaim not caught: "${claim}"`);
    assert.ok(check.violations.some((v) => v.code === 'prose-overclaim'));
  }

  // …while the required boundary statement itself must pass.
  const boundary = {
    ...structuredClone(result),
    prose_summary: 'This is validation-context evidence only; separate production-safety consideration still applies and no coverage statement is made.',
  };
  assert.equal(checkResultInvariants(boundary).ok, true);
});

test('every result binds exact candidate identity, digest, and translation ancestry', async () => {
  const { request } = await scenario('CONF-03');
  const { result } = await runToCompletion(request);
  assert.ok(result.subject.candidate_digest.startsWith('sha256:'));
  assert.ok(result.input_bindings.translated_candidate_result_id);
  assert.ok(result.input_bindings.attack_suite_digest.startsWith('sha256:'));
  assert.ok(result.input_bindings.profile_version_digest.startsWith('sha256:'));
});

test('a reference bundle is durable for every result and needs no rerun to review', async () => {
  const { request } = await scenario('CONF-04');
  const { result } = await runToCompletion(request);
  const { status, body } = await call(`/v1/defense-validation-results/${result.result_id}/reference-bundle`);
  assert.equal(status, 200);
  assert.ok(body.manifest.length > 0);
  assert.ok(body.case_record.attack_observations.length > 0);
  assert.ok(body.decision_record.precedence_trace.length === 8);
  const first = await call(body.manifest[0].locator);
  assert.equal(first.status, 200);
});

/* ----------------------------------------------------- examples on disk */

test('example payloads are read from the examples/ directory and are directly submittable', async () => {
  const { readFileSync } = await import('node:fs');
  const { body } = await call('/v1/example-payloads');
  assert.ok(body.examples.length >= 12);
  assert.match(body.directory, /examples$/);

  // Each indexed file is a bare payload, submittable with no unwrapping.
  const first = body.examples[0];
  const onDisk = JSON.parse(readFileSync(`${body.directory}/${first.file}`, 'utf8'));
  assert.deepEqual(onDisk, first.request);
  assert.equal(onDisk.contract_id, 'defense-validation@1.0');

  const check = await call('/v1/defense-validation-runs/validate', { method: 'POST', body: JSON.stringify(onDisk) });
  assert.equal(check.body.valid, true);
});

/* ---------------------------------------------------------- the ledger */

test('every durable result is appended to the ledger', async () => {
  const before = (await call('/v1/ledger')).body;

  const { request } = await scenario('CONF-03');
  const { result } = await runToCompletion(request);

  const after = (await call('/v1/ledger')).body;
  // Runs from earlier tests may still be completing in the background, so this
  // asserts the record grew and contains this result, not an exact count.
  assert.ok(after.total > before.total);

  const entry = after.entries.find((e) => e.result_id === result.result_id);
  assert.ok(entry, 'result missing from the ledger');
  assert.equal(entry.terminal_state, 'failed-to-block');
  assert.equal(entry.candidate_digest, result.subject.candidate_digest);
  assert.equal(entry.attack_cases, result.attack_observations.filter((o) => o.required).length);
  assert.ok(entry.recorded_at);
});

test('the result is stored as a queryable jsonb document', async () => {
  const { query } = await import('../src/adapters/db.js');
  const { request } = await scenario('CONF-04');
  const { result } = await runToCompletion(request);

  // The stored document is the emitted result, byte-for-byte after round-trip.
  const { rows } = await query('SELECT result, terminal_state, candidate_digest FROM defense_validation_result WHERE result_id = $1', [result.result_id]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].terminal_state, 'unsafe');
  assert.equal(rows[0].candidate_digest, result.subject.candidate_digest);
  assert.deepEqual(rows[0].result, result);

  // Nested facts are reachable in SQL without unpacking in the application.
  const nested = await query(
    `SELECT o ->> 'case_id' AS case_id
     FROM defense_validation_result r, jsonb_array_elements(r.result -> 'benign_observations') o
     WHERE r.result_id = $1 AND o ->> 'conclusion' = 'regressed'
     ORDER BY 1`,
    [result.result_id],
  );
  assert.deepEqual(
    nested.rows.map((r) => r.case_id),
    result.benign_observations.filter((o) => o.conclusion === 'regressed').map((o) => o.case_id).sort(),
  );

  // The GIN-indexed containment query the ledger relies on.
  const contained = await query(`SELECT count(*)::int AS n FROM defense_validation_result WHERE result @> '{"terminal_state":"unsafe"}'`);
  assert.ok(contained.rows[0].n >= 1);
});

test('the database refuses to rewrite or delete a stored result', async () => {
  const { query } = await import('../src/adapters/db.js');
  const { request } = await scenario('CONF-03');
  const { result } = await runToCompletion(request);

  // Immutability is enforced by the store itself, not by convention (§11.1).
  await query(`UPDATE defense_validation_result SET terminal_state = 'validated', result = '{"tampered":true}'::jsonb WHERE result_id = $1`, [result.result_id]);
  await query('DELETE FROM defense_validation_result WHERE result_id = $1', [result.result_id]);

  const { rows } = await query('SELECT terminal_state, result FROM defense_validation_result WHERE result_id = $1', [result.result_id]);
  assert.equal(rows.length, 1, 'result was deleted');
  assert.equal(rows[0].terminal_state, 'failed-to-block');
  assert.deepEqual(rows[0].result, result);

  // Re-inserting the same id is refused by the primary key, so first write wins.
  const before = (await call(`/v1/defense-validation-results/${result.result_id}`)).body;
  await assert.rejects(
    () => query(
      `INSERT INTO defense_validation_result (result_id, run_id, terminal_state, result)
       VALUES ($1,'x','validated','{"tampered":true}'::jsonb)`,
      [result.result_id],
    ),
    (err) => err.code === '23505',
  );
  assert.deepEqual((await call(`/v1/defense-validation-results/${result.result_id}`)).body, before);
});

test('evidence and reference bundles are durable and independently addressable', async () => {
  const { query } = await import('../src/adapters/db.js');
  const { request } = await scenario('CONF-01');
  const { result } = await runToCompletion(request);

  const bundle = (await call(`/v1/defense-validation-results/${result.result_id}/reference-bundle`)).body;
  for (const item of bundle.manifest.slice(0, 3)) {
    const { rows } = await query('SELECT payload FROM evidence_object WHERE digest = $1', [item.digest]);
    assert.equal(rows.length, 1, `evidence ${item.digest} not durable`);
  }

  // The cleanup addendum is a NEW bundle revision; the original stays readable.
  const revisions = await query('SELECT bundle_digest, supersedes_bundle_digest FROM reference_bundle WHERE result_id = $1 ORDER BY built_at', [result.result_id]);
  assert.equal(revisions.rows.length, 2, 'expected an original bundle plus a cleanup revision');
  assert.equal(revisions.rows[1].supersedes_bundle_digest, revisions.rows[0].bundle_digest);
  assert.equal(bundle.bundle_digest, revisions.rows[1].bundle_digest, 'the latest revision should be served');
});

test('the ledger survives a restart of the database connection', async () => {
  const { request } = await scenario('CONF-06');
  const { result } = await runToCompletion(request);

  const { closeDatabase, initDatabase, selectResult, selectLedgerStats } = await import('../src/adapters/db.js');
  const before = await selectLedgerStats();

  await closeDatabase();
  await initDatabase();

  const after = await selectLedgerStats();
  assert.deepEqual(after, before);
  const reread = await selectResult(result.result_id);
  assert.equal(reread.terminal_state, 'inconclusive');
  assert.deepEqual(reread.retained_findings, result.retained_findings);
});

/* ------------------------------------------------ proof-strength honesty */

test('a discriminator probe cannot be relabelled into direct root-cause proof', async () => {
  // Same requests as CONF-02, relabelled to claim they reach the vulnerable
  // code path. The target's instrumentation — not the label — decides which
  // behavior was actually reached, so the claim must fail to establish.
  const { request } = await scenario('CONF-02');
  const mislabelled = structuredClone(request);
  mislabelled.attack_suite.attack_suite_id = 'attack-suite:mislabelled:1';
  for (const attackCase of mislabelled.attack_suite.cases) {
    attackCase.proof_strength = 'direct';
    attackCase.expected_absent_behavior = 'reached-vulnerable-behavior';
  }

  const { result } = await runToCompletion(mislabelled);
  assert.equal(result.terminal_state, 'inconclusive');
  assert.equal(result.proof_strength, 'not-established');
  for (const observation of result.attack_observations) {
    assert.equal(observation.conclusion, 'undetermined');
    assert.equal(observation.candidate_absent_observation, 'unobservable');
    assert.ok(observation.gaps.some((g) => g.code === 'baseline-behavior-not-demonstrated'));
  }
});

test('the discriminator endpoint does not exercise the vulnerable code path', async () => {
  // The distinction between direct and indirect proof is only meaningful if the
  // stand-in endpoint genuinely cannot report vulnerable behavior.
  const payload = { method: 'GET', path: '/internal/probe/cve-2026-1234', query: "filter=1'%20OR%20'1'='1", body: null };
  const probe = await fetch(`${process.env.SIM_BASE_URL}/waf/v1/instances/waf-payments-dev/traffic`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const { target } = await probe.json();
  assert.deepEqual(target.markers, ['discriminator-target']);

  // The identical payload on the vulnerable endpoint does reach it.
  const real = await fetch(`${process.env.SIM_BASE_URL}/waf/v1/instances/waf-payments-dev/traffic`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...payload, path: '/api/orders' }),
  });
  const realTarget = (await real.json()).target;
  assert.deepEqual(realTarget.markers, ['vulnerable-behavior']);
});

/* --------------------------------- self-contained payload (no registry) */

test('the candidate digest is derived from the supplied artifact, not trusted from the payload', async () => {
  const { request } = await scenario('CONF-01');

  // A caller-asserted digest that disagrees with the artifact is refused
  // rather than recorded, so a verdict can never bind to the wrong material.
  const lying = structuredClone(request);
  lying.control_candidate.digest = 'sha256:0000000000000000000000000000000000000000000000000000000000000000';
  const rejected = await call('/v1/defense-validation-runs?force=true', { method: 'POST', body: JSON.stringify(lying) });
  assert.equal(rejected.status, 422);
  assert.equal(rejected.body.error.code, 'artifact-resolution-failure');

  // A correct assertion passes and matches what the result binds to.
  const truthful = structuredClone(request);
  const { derived_identities } = (await call('/v1/defense-validation-runs/validate', { method: 'POST', body: JSON.stringify(truthful) })).body;
  truthful.control_candidate.digest = derived_identities.candidate_digest;
  const { result } = await runToCompletion(truthful);
  assert.equal(result.subject.candidate_digest, derived_identities.candidate_digest);
});

test('editing the payload changes the outcome without touching the service', async () => {
  // Same context and suites; the caller simply narrows the candidate's rules.
  const { request } = await scenario('CONF-01');
  const weakened = structuredClone(request);
  weakened.control_candidate.control_candidate_id = 'control-candidate:ad-hoc:1';
  weakened.control_candidate.artifact.rules = weakened.control_candidate.artifact.rules.filter((r) => r.pattern.includes('union'));

  const { result } = await runToCompletion(weakened);
  assert.equal(result.terminal_state, 'failed-to-block');
  assert.equal(result.subject.control_candidate_id, 'control-candidate:ad-hoc:1');
  const blocked = result.attack_observations.filter((o) => o.conclusion === 'blocked-as-required');
  assert.equal(blocked.length, 1, 'only the UNION SELECT case should be blocked by the narrowed candidate');
});

test('the payload is validated field by field with addressable errors', async () => {
  const { request } = await scenario('CONF-01');

  const broken = structuredClone(request);
  delete broken.attack_suite.cases[1].proof_strength;
  broken.attack_suite.cases[0].expected_absent_behavior = 'reached-something-else';
  broken.control_candidate.artifact.rules[0].pattern = '([a-z]+';
  broken.validation_policy.required_attack_cases = ['atk-does-not-exist'];

  const response = await call('/v1/defense-validation-runs', { method: 'POST', body: JSON.stringify(broken) });
  assert.equal(response.status, 400);
  const fields = response.body.error.details.map((d) => d.field);
  assert.ok(fields.includes('attack_suite.cases[1].proof_strength'));
  assert.ok(fields.includes('attack_suite.cases[0].expected_absent_behavior'));

  // Cross-field checks only run once the shape is sound.
  const shapeOk = structuredClone(request);
  shapeOk.control_candidate.artifact.rules[0].pattern = '([a-z]+';
  shapeOk.validation_policy.required_attack_cases = ['atk-does-not-exist'];
  const second = await call('/v1/defense-validation-runs', { method: 'POST', body: JSON.stringify(shapeOk) });
  assert.equal(second.status, 400);
  const secondFields = second.body.error.details.map((d) => d.field);
  assert.ok(secondFields.includes('control_candidate.artifact.rules[0].pattern'));
  assert.ok(secondFields.includes('validation_policy.required_attack_cases'));
});

test('the dry-run validator reports validity without executing anything', async () => {
  const { request } = await scenario('CONF-01');
  const before = (await call('/v1/defense-validation-runs')).body.runs.length;

  const ok = await call('/v1/defense-validation-runs/validate', { method: 'POST', body: JSON.stringify(request) });
  assert.equal(ok.body.valid, true);
  assert.ok(ok.body.derived_identities.candidate_digest.startsWith('sha256:'));

  const bad = await call('/v1/defense-validation-runs/validate', { method: 'POST', body: JSON.stringify({ contract_id: 'defense-validation@1.0' }) });
  assert.equal(bad.body.valid, false);
  assert.ok(bad.body.errors.some((e) => e.field === 'control_candidate'));

  assert.equal((await call('/v1/defense-validation-runs')).body.runs.length, before, 'validation must not create runs');
});

test('a payload cannot name an adapter this deployment does not operate', async () => {
  const { request } = await scenario('CONF-01');

  const badRunner = structuredClone(request);
  badRunner.validation_context.execution = { runner_adapter_id: 'runner-adapter-arbitrary-shell:1' };
  const runnerResponse = await call('/v1/defense-validation-runs', { method: 'POST', body: JSON.stringify(badRunner) });
  assert.equal(runnerResponse.status, 400);
  assert.ok(runnerResponse.body.error.details.some((d) => d.field === 'validation_context.execution.runner_adapter_id'));

  const badControl = structuredClone(request);
  badControl.validation_context.candidate_application.adapter_id = 'control-adapter-production-edge:1';
  const controlResponse = await call('/v1/defense-validation-runs', { method: 'POST', body: JSON.stringify(badControl) });
  assert.equal(controlResponse.status, 400);
  assert.ok(controlResponse.body.error.details.some((d) => d.field === 'validation_context.candidate_application.adapter_id'));
});

test('service limits hold regardless of what the supplied policy claims', async () => {
  const { request } = await scenario('CONF-01');

  const tooManyRules = structuredClone(request);
  tooManyRules.control_candidate.artifact.rules = Array.from({ length: 60 }, (_, i) => ({
    rule_id: `bulk-${i}`, target: 'ANY', operator: 'rx', pattern: `bulk${i}`, action: 'deny', status: 403,
  }));
  const rulesResponse = await call('/v1/defense-validation-runs', { method: 'POST', body: JSON.stringify(tooManyRules) });
  assert.equal(rulesResponse.status, 400);

  // A payload raising its own case budget still cannot exceed the service cap.
  const oversizedPattern = structuredClone(request);
  oversizedPattern.validation_policy.max_cases_per_run = 100000;
  oversizedPattern.control_candidate.artifact.rules[0].pattern = 'a'.repeat(600);
  const patternResponse = await call('/v1/defense-validation-runs', { method: 'POST', body: JSON.stringify(oversizedPattern) });
  assert.equal(patternResponse.status, 400);
  assert.ok(patternResponse.body.error.details.some((d) => d.field === 'control_candidate.artifact.rules[0].pattern'));
});

/* ------------------------------------------- candidate cleanup §5.2/§12.2 */

test('the candidate is removed after the result is durable, and the removal is evidenced', async () => {
  const { request } = await scenario('CONF-01');
  const { run } = await runToCompletion(request);

  // The run timeline must include the post-result persist and cleanup steps.
  const names = run.steps.map((s) => s.name);
  assert.ok(names.includes('persist-result-bundle-and-outbox'), 'persist step missing from the run timeline');
  assert.ok(names.includes('remove-or-reset-candidate'), 'cleanup step missing from the run timeline');

  const fresh = await call(`/v1/defense-validation-runs/${run.run_id}`);
  assert.equal(fresh.body.cleanup_record.removed, true);
  assert.ok(fresh.body.cleanup_record.evidence_ref);

  // The context is genuinely clean again, so the next run can establish baseline.
  const sim = await fetch(`${process.env.SIM_BASE_URL}/waf/v1/instances/waf-payments-dev`);
  const instance = await sim.json();
  assert.deepEqual(instance.active_applications, [], 'candidate was left behind on the control');

  // The reference bundle carries the removal evidence as an explicit addendum.
  const bundle = await call(`/v1/defense-validation-results/${run.result_id}/reference-bundle`);
  assert.equal(bundle.body.post_result_addendum.kind, 'candidate-removal-and-reset');
  assert.equal(bundle.body.post_result_addendum.removed, true);
  assert.ok(bundle.body.supersedes_bundle_digest.startsWith('sha256:'));
});

test('after an indeterminate apply, removal is withheld pending reconciliation', async () => {
  const { request } = await scenario('CONF-08');
  const { run, result } = await runToCompletion(request);

  assert.equal(result.terminal_state, 'malfunction');
  const cleanupStep = run.steps.find((s) => s.name === 'remove-or-reset-candidate');
  assert.equal(cleanupStep.status, 'reconciliation-required');

  const fresh = await call(`/v1/defense-validation-runs/${run.run_id}`);
  assert.equal(fresh.body.cleanup_record.reconciliation_required, true);
  assert.equal(fresh.body.cleanup_record.removed, false);
});

/* ------------------------------------------------------- security §16.3 */

test('SEC-01: a production validation context is denied at the edge', async () => {
  const { request } = await scenario('SEC-01');
  const response = await call('/v1/defense-validation-runs', { method: 'POST', body: JSON.stringify(request) });
  assert.equal(response.status, 403);
  assert.equal(response.body.error.code, 'production-context-denied');
});

test('SEC-02: unauthenticated and under-privileged submission is rejected', async () => {
  const { request } = await scenario('CONF-01');
  const anonymous = await fetch(`${API}/v1/defense-validation-runs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  });
  assert.equal(anonymous.status, 401);

  const viewer = await fetch(`${API}/v1/defense-validation-runs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer dev-viewer-token' },
    body: JSON.stringify(request),
  });
  assert.equal(viewer.status, 403);
});

test('SEC-03: the contract rejects unknown fields and wrong contract ids', async () => {
  const { request } = await scenario('CONF-01');
  const extra = await call('/v1/defense-validation-runs', { method: 'POST', body: JSON.stringify({ ...request, expected_terminal_state: 'validated' }) });
  assert.equal(extra.status, 400);
  assert.ok(extra.body.error.details.some((d) => d.field === 'expected_terminal_state'));

  // Nested unknown fields are refused too, so a payload cannot smuggle in
  // semantics the contract does not define.
  const nested = structuredClone(request);
  nested.validation_policy.override_terminal_state = 'validated';
  const nestedResponse = await call('/v1/defense-validation-runs', { method: 'POST', body: JSON.stringify(nested) });
  assert.equal(nestedResponse.status, 400);
  assert.ok(nestedResponse.body.error.details.some((d) => d.field === 'validation_policy.override_terminal_state'));

  const wrongContract = await call('/v1/defense-validation-runs', { method: 'POST', body: JSON.stringify({ ...request, contract_id: 'defense-validation@2.0' }) });
  assert.equal(wrongContract.status, 400);
});

test('SEC-05: context identifiers cannot steer an adapter off its route', async () => {
  const { request } = await scenario('CONF-01');

  // A traversal in instance_id would otherwise normalize away the API prefix
  // and reach an unrelated endpoint on the control-plane host.
  for (const [field, mutate] of [
    ['validation_context.candidate_application.instance_id',
      (p) => { p.validation_context.candidate_application.instance_id = 'x/../../../../admin/v1/reset'; }],
    ['validation_context.candidate_application.target_policy_ref',
      (p) => { p.validation_context.candidate_application.target_policy_ref = '../../../../admin/v1/reset'; }],
    ['validation_context.execution.simulator_id',
      (p) => { p.validation_context.execution.simulator_id = 'sim/../../etc'; }],
  ]) {
    const payload = structuredClone(request);
    mutate(payload);
    const response = await call('/v1/defense-validation-runs', { method: 'POST', body: JSON.stringify(payload) });
    assert.equal(response.status, 400, `${field} was accepted`);
    assert.ok(response.body.error.details.some((d) => d.field === field), `${field} not reported`);
  }

  // Encoded separators are refused too, not just literal ones.
  const encoded = structuredClone(request);
  encoded.validation_context.candidate_application.instance_id = 'x%2F..%2F..%2Fadmin';
  const encodedResponse = await call('/v1/defense-validation-runs', { method: 'POST', body: JSON.stringify(encoded) });
  assert.equal(encodedResponse.status, 400);
});

test('SEC-05b: the adapter encodes path segments even if validation is bypassed', async () => {
  // Defence in depth: call the adapter directly with a hostile identifier the
  // contract would have rejected, and confirm it stays on its own route.
  const { modsecurityControlAdapter } = await import('../src/adapters/control/modsecurity.js');
  const hostile = {
    isolation: { environment: 'non-prod' },
    candidate_application: { instance_id: 'x/../../../../admin/v1/reset', target_policy_ref: 'p' },
  };
  await assert.rejects(
    () => modsecurityControlAdapter.describeContext(hostile),
    (err) => err.category === 'candidate-application-failure',
    'traversal should 404 against the encoded instance path, not reach the admin endpoint',
  );

  // The lab is still intact — nothing was reset.
  const probe = await fetch(`${process.env.SIM_BASE_URL}/waf/v1/instances/waf-payments-dev`);
  assert.equal(probe.status, 200);
});

test('SEC-04: case material cannot redirect the runner off the declared ingress', async () => {
  const { admitRequest } = await import('../src/adapters/runner/local_http.js');
  assert.throws(() => admitRequest({ method: 'GET', path: 'http://evil.example/steal' }));
  assert.throws(() => admitRequest({ method: 'GET', path: '/../../admin' }));
  assert.throws(() => admitRequest({ method: 'CONNECT', path: '/' }));
});

/* ------------------------------------------ replay, idempotency §12.3 */

test('an identical payload deduplicates, and force bypasses it', async () => {
  const { request } = await scenario('CONF-01');
  // Give this payload its own replay identity so no other test's submissions
  // can satisfy or spoil the assertions below.
  request.control_candidate.control_candidate_id = 'control-candidate:replay-identity:1';

  const first = await call('/v1/defense-validation-runs', { method: 'POST', body: JSON.stringify(request) });
  assert.equal(first.status, 202);
  assert.ok(!first.body.deduplicated);
  assert.ok(first.body.replay_key.startsWith('sha256:'));

  const second = await call('/v1/defense-validation-runs', { method: 'POST', body: JSON.stringify(request) });
  assert.equal(second.status, 200);
  assert.equal(second.body.deduplicated, true);
  assert.equal(second.body.run_id, first.body.run_id, 'dedupe must point at the original run');
  assert.equal(second.body.replay_key, first.body.replay_key);

  const forced = await call('/v1/defense-validation-runs?force=true', { method: 'POST', body: JSON.stringify(request) });
  assert.equal(forced.status, 202);
  assert.notEqual(forced.body.run_id, first.body.run_id, 'force must execute a fresh run');
  // The identity itself is unchanged; only the dedupe check is bypassed.
  assert.equal(forced.body.replay_key, first.body.replay_key);
});

/* ---------------------------------------------------- determinism §16.4 */

test('the aggregate engine is order-independent and repeatable', async () => {
  const { resolveAggregate } = await import('../src/domain/aggregate_result.js');
  const attackCases = [
    { case_id: 'a1', conclusion: 'blocked-as-required', proof_strength: 'direct', gaps: [] },
    { case_id: 'a2', conclusion: 'not-blocked', proof_strength: 'direct', gaps: [] },
    { case_id: 'a3', conclusion: 'undetermined', proof_strength: 'direct', gaps: [{ code: 'x' }] },
  ];
  const benignCases = [
    { case_id: 'b1', conclusion: 'preserved', gaps: [] },
    { case_id: 'b2', conclusion: 'regressed', gaps: [] },
  ];
  const base = {
    admission: { admitted: true, findings: [] },
    contextAssessment: { status: 'valid', findings: [] },
    malfunction: null,
    candidateApplication: { state_established: true, state: 'candidate-present-verified' },
    requiredCaseIds: { attack: ['a1', 'a2', 'a3'], benign: ['b1', 'b2'] },
  };

  const forward = resolveAggregate({ ...base, attackCases, benignCases });
  const reversed = resolveAggregate({ ...base, attackCases: [...attackCases].reverse(), benignCases: [...benignCases].reverse() });

  assert.equal(forward.terminal_state, 'unsafe');
  assert.equal(reversed.terminal_state, 'unsafe');
  assert.equal(forward.decided_by.name, reversed.decided_by.name);
  // Both the attack failure and the unresolved case survive the verdict.
  assert.deepEqual(forward.retained_findings.attack_failures, ['a2']);
  assert.equal(forward.retained_findings.unresolved_required_evidence.length, 1);
});

test('unknown candidate application state blocks every supported candidate judgment', async () => {
  const { resolveAggregate } = await import('../src/domain/aggregate_result.js');
  const outcome = resolveAggregate({
    admission: { admitted: true, findings: [] },
    contextAssessment: { status: 'valid', findings: [] },
    malfunction: null,
    candidateApplication: { state_established: false, state: 'candidate-state-unverified' },
    attackCases: [{ case_id: 'a1', conclusion: 'blocked-as-required', proof_strength: 'direct', gaps: [] }],
    benignCases: [{ case_id: 'b1', conclusion: 'regressed', gaps: [] }],
    requiredCaseIds: { attack: ['a1'], benign: ['b1'] },
  });
  assert.equal(outcome.terminal_state, 'inconclusive');
  assert.equal(outcome.decided_by.name, 'candidate-state-not-established');
});

test('proof-strength aggregation covers direct, indirect, mixed and not-established', async () => {
  const { aggregateProofStrength } = await import('../src/domain/case_evaluation.js');
  const blocked = (proof) => ({ conclusion: 'blocked-as-required', proof_strength: proof });
  assert.equal(aggregateProofStrength([blocked('direct'), blocked('direct')]), 'direct');
  assert.equal(aggregateProofStrength([blocked('indirect')]), 'indirect');
  assert.equal(aggregateProofStrength([blocked('direct'), blocked('indirect')]), 'mixed');
  assert.equal(aggregateProofStrength([blocked('direct'), { conclusion: 'undetermined', proof_strength: 'direct' }]), 'not-established');
  assert.equal(aggregateProofStrength([]), 'not-established');
});
