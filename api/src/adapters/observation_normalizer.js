/**
 * Observation Correlator / Normalizer (§6.6).
 *
 * Collapses runner-specific and vendor-specific payloads into one normalized
 * observation vocabulary, correlating control decision, target receipt, case
 * identity, and the candidate application that was live at the time.
 *
 * Anything that cannot be correlated becomes an explicit `error` on the
 * observation — never a silent absence, and never an assumed outcome.
 */
export function normalizeExecution(execution, { caseId, trial, expectedApplicationIds }) {
  const transactions = execution.transactions ?? [];
  if (transactions.length === 0) {
    return { case_id: caseId, trial, runner: execution.runner, execution_ref: execution.execution_ref, error: 'runner returned no correlatable transaction' };
  }
  // Multi-step vendor scenarios: the control decision belongs to the first
  // denied step, otherwise the final step's outcome stands for the case.
  const decisive = transactions.find((t) => t.control?.decision === 'deny') ?? transactions[transactions.length - 1];

  const observation = {
    case_id: caseId,
    trial,
    runner: execution.runner,
    execution_ref: execution.execution_ref,
    vendor_verdict: execution.vendor_verdict ?? null,
    transaction_id: decisive.transaction_id,
    observed_at: decisive.received_at,
    control: {
      observed: Boolean(decisive.control),
      decision: decisive.control?.decision ?? null,
      status_code: decisive.control?.status_code ?? null,
      matched_rule_id: decisive.control?.matched_rule_id ?? null,
      matched_policy_ref: decisive.control?.matched_policy_ref ?? null,
      active_candidate_digest: decisive.control?.active_candidate_digest ?? null,
      attribution_available: Boolean(decisive.control?.attribution_available),
      active_application_ids: decisive.control?.active_application_ids ?? [],
    },
    target: decisive.target
      ? {
          observed: true,
          reached: decisive.target.reached,
          status_code: decisive.target.status_code,
          markers: decisive.target.markers ?? [],
          receipt_id: decisive.target.receipt_id,
        }
      : { observed: false, reached: false, markers: [] },
    step_count: transactions.length,
  };

  // Correlation guard: the trial must have run against the candidate state we
  // believe was live, otherwise the observation is not attributable to it.
  if (expectedApplicationIds) {
    const live = observation.control.active_application_ids ?? [];
    const matches =
      expectedApplicationIds.length === live.length && expectedApplicationIds.every((id) => live.includes(id));
    if (!matches) {
      observation.correlation_warning = `observation was taken with active applications [${live.join(', ') || 'none'}], expected [${expectedApplicationIds.join(', ') || 'none'}]`;
      observation.error = observation.correlation_warning;
    }
  }

  return observation;
}
