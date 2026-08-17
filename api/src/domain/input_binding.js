/**
 * Input binding (§5.2 steps 1–5).
 *
 * The request carries the material itself rather than references, so "resolving
 * inputs" means deriving the identities the result must bind to: a digest over
 * the exact native artifact, and digests over each supplied suite, context
 * descriptor, profile, and policy exactly as submitted.
 *
 * Deriving digests here — rather than trusting a digest in the payload — is what
 * keeps the exact-candidate-binding invariant honest when there is no registry
 * to appeal to. A digest supplied by the requestor is treated as an assertion to
 * check, never as the answer.
 */
import { sha256 } from '../../../lib/digest.js';

export class InputBindingError extends Error {
  constructor(message, field) {
    super(message);
    this.category = 'artifact-resolution-failure';
    this.field = field;
  }
}

export function bindSuppliedInputs(request) {
  const candidateDigest = sha256(request.control_candidate.artifact);

  if (request.control_candidate.digest && request.control_candidate.digest !== candidateDigest) {
    throw new InputBindingError(
      `supplied candidate digest does not match the supplied artifact (derived ${candidateDigest})`,
      'control_candidate.digest',
    );
  }

  return {
    candidate: { ...request.control_candidate, digest: candidateDigest },
    attackSuite: { ...request.attack_suite, digest: sha256(request.attack_suite) },
    benignSuite: { ...request.benign_suite, digest: sha256(request.benign_suite) },
    context: { ...request.validation_context, descriptor_digest: sha256(request.validation_context) },
    profile: { ...request.validation_profile, version_digest: sha256(request.validation_profile) },
    policy: { ...request.validation_policy, version_digest: sha256(request.validation_policy) },
  };
}

/** Compact identity summary for run listings, so list views never parse the payload. */
export function summarizeInputs(bound) {
  return {
    control_candidate_id: bound.candidate.control_candidate_id,
    candidate_digest: bound.candidate.digest,
    target_technology: bound.candidate.target_technology,
    validation_context_id: bound.context.validation_context_id,
    validation_context_label: bound.context.label ?? bound.context.validation_context_id,
    attack_suite_id: bound.attackSuite.attack_suite_id,
    benign_suite_id: bound.benignSuite.benign_suite_id,
    validation_profile_id: bound.profile.validation_profile_id,
    validation_policy_id: bound.policy.validation_policy_id,
  };
}
