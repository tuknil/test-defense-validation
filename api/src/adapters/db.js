/**
 * Embedded PostgreSQL (§11.1, §4.2 "PostgreSQL — state/result/outbox").
 *
 * PGlite is a real PostgreSQL compiled to WASM and run in-process, so the
 * schema, types, and SQL below are the same ones a managed PostgreSQL would
 * take. Swapping in `pg` against a server means changing the connection, not
 * the queries.
 *
 * Storage shape: the authoritative document lives in a `jsonb` column, with the
 * few dimensions the ledger actually filters and sorts on lifted into typed
 * columns beside it. That keeps the result exactly as the engine emitted it —
 * no lossy flattening — while still allowing indexed queries.
 *
 * Immutability is enforced by the database, not by convention. `defense_validation_result`
 * and `evidence_object` carry rules that make UPDATE and DELETE no-ops, so a
 * result cannot be rewritten after the fact even by a bug (§11.1, ADR-005).
 */
import { PGlite } from '@electric-sql/pglite';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DATA_DIR = process.env.DATA_DIR ?? path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../data');
export const DB_DIR = path.join(DATA_DIR, 'pgdata');

let db = null;
let ready = null;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS defense_validation_result (
  result_id             TEXT PRIMARY KEY,
  run_id                TEXT NOT NULL,
  recorded_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  produced_at           TIMESTAMPTZ,
  terminal_state        TEXT NOT NULL,
  proof_strength        TEXT,
  control_candidate_id  TEXT,
  candidate_digest      TEXT,
  validation_context_id TEXT,
  replay_key            TEXT,
  result                JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS dvr_recorded_at_idx    ON defense_validation_result (recorded_at DESC);
CREATE INDEX IF NOT EXISTS dvr_terminal_state_idx ON defense_validation_result (terminal_state);
CREATE INDEX IF NOT EXISTS dvr_candidate_idx      ON defense_validation_result (control_candidate_id);
CREATE INDEX IF NOT EXISTS dvr_result_gin         ON defense_validation_result USING GIN (result);

CREATE TABLE IF NOT EXISTS evidence_object (
  digest      TEXT PRIMARY KEY,
  kind        TEXT,
  run_id      TEXT,
  stored_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  claim_types TEXT[] NOT NULL DEFAULT '{}',
  payload     JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS evidence_run_idx ON evidence_object (run_id);

-- Bundles are append-only too: the post-result cleanup addendum is written as a
-- NEW row that supersedes the previous digest, so the original stays readable.
CREATE TABLE IF NOT EXISTS reference_bundle (
  bundle_digest            TEXT PRIMARY KEY,
  result_id                TEXT NOT NULL,
  built_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
  supersedes_bundle_digest TEXT,
  bundle                   JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS bundle_result_idx ON reference_bundle (result_id, built_at DESC);
`;

// Rules cannot use IF NOT EXISTS, so they are created once behind a catalog check.
const RULES = [
  ['dvr_no_update', 'CREATE RULE dvr_no_update AS ON UPDATE TO defense_validation_result DO INSTEAD NOTHING'],
  ['dvr_no_delete', 'CREATE RULE dvr_no_delete AS ON DELETE TO defense_validation_result DO INSTEAD NOTHING'],
  ['bundle_no_update', 'CREATE RULE bundle_no_update AS ON UPDATE TO reference_bundle DO INSTEAD NOTHING'],
  ['bundle_no_delete', 'CREATE RULE bundle_no_delete AS ON DELETE TO reference_bundle DO INSTEAD NOTHING'],
  ['evidence_no_delete', 'CREATE RULE evidence_no_delete AS ON DELETE TO evidence_object DO INSTEAD NOTHING'],
];

export function initDatabase() {
  if (ready) return ready;
  ready = (async () => {
    // PGlite's own mkdir is not recursive, so the parent must exist first.
    mkdirSync(DB_DIR, { recursive: true });
    db = await PGlite.create({ dataDir: DB_DIR });
    await db.exec(SCHEMA);
    for (const [name, statement] of RULES) {
      const existing = await db.query('SELECT 1 FROM pg_rules WHERE rulename = $1', [name]);
      if (existing.rows.length === 0) await db.exec(statement);
    }
    return db;
  })();
  return ready;
}

async function client() {
  if (!db) await initDatabase();
  return db;
}

export async function query(sql, params = []) {
  const pg = await client();
  return pg.query(sql, params);
}

/**
 * PostgreSQL forbids ON CONFLICT on a table carrying INSERT/UPDATE rules, and
 * the append-only rules are the stronger guarantee — so first-write-wins is
 * enforced by the primary key instead, with the duplicate swallowed. Re-writing
 * the same identity is exactly what must not happen, so ignoring it is correct.
 */
async function insertFirstWriteWins(sql, params) {
  try {
    await query(sql, params);
    return true;
  } catch (err) {
    if (err?.code === '23505') return false; // already recorded; the original stands
    throw err;
  }
}

export async function closeDatabase() {
  if (db) {
    await db.close();
    db = null;
    ready = null;
  }
}

/* ------------------------------------------------------------- results */

export async function insertResult(result) {
  return insertFirstWriteWins(
    `INSERT INTO defense_validation_result
       (result_id, run_id, produced_at, terminal_state, proof_strength,
        control_candidate_id, candidate_digest, validation_context_id, replay_key, result)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
    [
      result.result_id,
      result.run_id,
      result.produced_at ?? null,
      result.terminal_state,
      result.proof_strength ?? null,
      result.subject?.control_candidate_id ?? null,
      result.subject?.candidate_digest ?? null,
      result.input_bindings?.validation_context_id ?? null,
      result.input_bindings?.replay_key ?? null,
      JSON.stringify(result),
    ],
  );
}

export async function selectResult(resultId) {
  const { rows } = await query('SELECT result FROM defense_validation_result WHERE result_id = $1', [resultId]);
  return rows[0]?.result ?? null;
}

/**
 * The ledger view. Counts of required cases are computed in SQL over the jsonb
 * document rather than pulled into the application, which is the point of
 * keeping the whole result queryable.
 */
export async function selectLedger({ terminalState = null, limit = 200 } = {}) {
  const { rows } = await query(
    `SELECT
       result_id, run_id, recorded_at, produced_at, terminal_state, proof_strength,
       control_candidate_id, candidate_digest, validation_context_id, replay_key,
       result #>> '{subject,target_technology}'            AS target_technology,
       result #>> '{input_bindings,attack_suite_id}'       AS attack_suite_id,
       result #>> '{input_bindings,benign_suite_id}'       AS benign_suite_id,
       result #>> '{input_bindings,validation_profile_id}' AS validation_profile_id,
       result #>> '{input_bindings,validation_policy_id}'  AS validation_policy_id,
       result -> 'decided_by'                             AS decided_by,
       jsonb_array_length(COALESCE(result -> 'limitations', '[]'::jsonb)) AS limitations,
       (SELECT count(*) FROM jsonb_array_elements(result -> 'attack_observations') o
          WHERE (o ->> 'required')::boolean)                                    AS attack_cases,
       (SELECT count(*) FROM jsonb_array_elements(result -> 'attack_observations') o
          WHERE (o ->> 'required')::boolean
            AND o ->> 'conclusion' = 'blocked-as-required')                     AS attack_blocked,
       (SELECT count(*) FROM jsonb_array_elements(result -> 'benign_observations') o
          WHERE (o ->> 'required')::boolean)                                    AS benign_cases,
       (SELECT count(*) FROM jsonb_array_elements(result -> 'benign_observations') o
          WHERE (o ->> 'required')::boolean
            AND o ->> 'conclusion' = 'preserved')                               AS benign_preserved
     FROM defense_validation_result
     WHERE ($1::text IS NULL OR terminal_state = $1)
     ORDER BY recorded_at DESC
     LIMIT $2`,
    [terminalState, limit],
  );
  return rows.map((r) => ({
    ...r,
    attack_cases: Number(r.attack_cases),
    attack_blocked: Number(r.attack_blocked),
    benign_cases: Number(r.benign_cases),
    benign_preserved: Number(r.benign_preserved),
    limitations: Number(r.limitations),
  }));
}

export async function selectLedgerStats() {
  const { rows } = await query(
    `SELECT terminal_state, count(*)::int AS count
     FROM defense_validation_result GROUP BY terminal_state`,
  );
  const distribution = Object.fromEntries(rows.map((r) => [r.terminal_state, r.count]));
  return { total: rows.reduce((sum, r) => sum + r.count, 0), terminal_state_distribution: distribution };
}

/** Case-conclusion rollups for /v1/metrics, aggregated inside the database. */
export async function selectCaseMetrics() {
  const roll = async (field) => {
    const { rows } = await query(
      `SELECT o ->> 'conclusion' AS conclusion, count(*)::int AS count
       FROM defense_validation_result r,
            jsonb_array_elements(r.result -> '${field}') o
       GROUP BY 1`,
    );
    return Object.fromEntries(rows.map((r) => [r.conclusion, r.count]));
  };
  const [attack, benign] = await Promise.all([roll('attack_observations'), roll('benign_observations')]);
  const { rows } = await query(
    `SELECT count(*)::int AS apply_failures
     FROM defense_validation_result
     WHERE result #> '{candidate_application,apply_failed}' = 'true'::jsonb`,
  );
  return { attack, benign, applyFailures: rows[0]?.apply_failures ?? 0 };
}

/* ------------------------------------------------------------ evidence */

export async function upsertEvidence(record) {
  // Content-addressed: the payload for a digest can never differ, so the only
  // legitimate change is accumulating the claim types the object supports.
  await query(
    `INSERT INTO evidence_object (digest, kind, run_id, stored_at, claim_types, payload)
     VALUES ($1,$2,$3,$4,$5,$6)
     ON CONFLICT (digest) DO UPDATE
       SET claim_types = (
         SELECT COALESCE(array_agg(DISTINCT c), '{}')
         FROM unnest(evidence_object.claim_types || EXCLUDED.claim_types) AS c
       )`,
    [record.digest, record.kind ?? null, record.run_id ?? null, record.stored_at, record.claim_types ?? [], JSON.stringify(record.payload)],
  );
}

export async function selectEvidence(digest) {
  const { rows } = await query('SELECT digest, kind, run_id, stored_at, claim_types, payload FROM evidence_object WHERE digest = $1', [digest]);
  return rows[0] ?? null;
}

export async function selectEvidenceList(runId) {
  const { rows } = await query(
    `SELECT digest, kind, run_id, stored_at, claim_types
     FROM evidence_object
     WHERE ($1::text IS NULL OR run_id = $1)
     ORDER BY stored_at`,
    [runId ?? null],
  );
  return rows;
}

/* ------------------------------------------------------------- bundles */

export async function insertBundle(bundle) {
  return insertFirstWriteWins(
    `INSERT INTO reference_bundle (bundle_digest, result_id, built_at, supersedes_bundle_digest, bundle)
     VALUES ($1,$2,$3,$4,$5)`,
    [bundle.bundle_digest, bundle.result_id, bundle.built_at ?? null, bundle.supersedes_bundle_digest ?? null, JSON.stringify(bundle)],
  );
}

/** Latest bundle for a result; earlier revisions stay retrievable by digest. */
export async function selectBundle(resultId) {
  const { rows } = await query(
    'SELECT bundle FROM reference_bundle WHERE result_id = $1 ORDER BY built_at DESC, ctid DESC LIMIT 1',
    [resultId],
  );
  return rows[0]?.bundle ?? null;
}

export async function selectBundleByDigest(digest) {
  const { rows } = await query('SELECT bundle FROM reference_bundle WHERE bundle_digest = $1', [digest]);
  return rows[0]?.bundle ?? null;
}
