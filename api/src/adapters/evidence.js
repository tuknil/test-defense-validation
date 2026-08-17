/**
 * Immutable evidence store + reference-bundle builder (§3.3, §11.2, ADR-005).
 *
 * Evidence is content-addressed: writing the same sanitized payload twice yields
 * the same locator. Everything is redacted on the way in, so secrets cannot
 * reach a bundle even if a vendor response carried them.
 *
 * Both live in embedded PostgreSQL as jsonb documents. Nothing is cached in
 * process — the database is the store, so a restart changes nothing about what
 * a reviewer can retrieve.
 */
import { sha256, nowIso } from '../../../lib/digest.js';
import { redact } from '../domain/invariants.js';
import { upsertEvidence, selectEvidence, selectEvidenceList, insertBundle, selectBundle, selectBundleByDigest } from './db.js';

export async function putEvidence({ kind, payload, claim_type, run_id }) {
  const sanitized = redact(payload);
  const digest = sha256(sanitized);
  const stored_at = nowIso();

  await upsertEvidence({
    digest,
    kind,
    run_id,
    stored_at,
    claim_types: claim_type ? [claim_type] : [],
    payload: sanitized,
  });

  return {
    evidence_ref: `evidence://${digest.replace('sha256:', '')}`,
    digest,
    kind,
    claim_type: claim_type ?? null,
    stored_at,
  };
}

export async function getEvidence(digestOrId) {
  const digest = digestOrId.startsWith('sha256:') ? digestOrId : `sha256:${digestOrId}`;
  return selectEvidence(digest);
}

export async function listEvidence(runId) {
  return selectEvidenceList(runId);
}

/**
 * Reference bundle: everything a reviewer needs to re-read the decision without
 * rerunning validation.
 */
export async function buildReferenceBundle(result, { evidenceRefs, runSteps, auditEvents }) {
  const bundle = {
    contract_id: 'DefenseValidationReferenceBundle@1',
    result_id: result.result_id,
    run_id: result.run_id,
    built_at: nowIso(),
    subject: result.subject,
    input_bindings: result.input_bindings,
    terminal_state: result.terminal_state,
    proof_strength: result.proof_strength,
    manifest: evidenceRefs.map((ref) => ({
      evidence_ref: ref.evidence_ref,
      digest: ref.digest,
      kind: ref.kind,
      claim_type: ref.claim_type,
      locator: `/v1/evidence/${ref.digest.replace('sha256:', '')}`,
    })),
    decision_record: {
      context_assessment: result.context_assessment,
      candidate_application: result.candidate_application,
      precedence_trace: result.precedence_trace,
      decided_by: result.decided_by,
      limitations: result.limitations,
    },
    case_record: {
      attack_observations: result.attack_observations,
      benign_observations: result.benign_observations,
    },
    execution_record: runSteps,
    audit_record: auditEvents,
    retention: result.retention,
  };
  bundle.bundle_digest = sha256(bundle);
  await insertBundle(bundle);
  return bundle;
}

export async function getReferenceBundle(resultId) {
  return selectBundle(resultId);
}

export async function getReferenceBundleByDigest(digest) {
  return selectBundleByDigest(digest);
}

/**
 * Candidate removal happens after the result is made durable (§5.2 step 16), so
 * its evidence cannot live inside the immutable result — nor inside the bundle
 * already written. It is stored as a NEW bundle revision that names the digest
 * it supersedes, leaving the original retrievable and the chain auditable.
 */
export async function attachCleanupAddendum(resultId, addendum) {
  const previous = await selectBundle(resultId);
  if (!previous) return null;

  const { bundle_digest, ...body } = previous;
  const updated = {
    ...body,
    built_at: nowIso(),
    post_result_addendum: {
      kind: 'candidate-removal-and-reset',
      captured_at: nowIso(),
      note: 'Captured after the authoritative result was made durable. It does not alter any domain conclusion.',
      ...addendum,
    },
    supersedes_bundle_digest: bundle_digest,
  };
  updated.bundle_digest = sha256(updated);
  await insertBundle(updated);
  return updated;
}
