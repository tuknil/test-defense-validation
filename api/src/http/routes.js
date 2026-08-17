/**
 * Private API surface (§6.1, §9).
 *
 * The API holds no control-mutation rights and no registry. It authenticates,
 * validates the self-contained payload against the contract, derives input
 * identities, applies the security boundary, computes replay identity, creates
 * the run, and enqueues. Every domain decision belongs to the worker.
 */
import { httpError } from '../../../lib/microhttp.js';
import { validateSubmitRequest, SUBMIT_REQUEST_SCHEMA, TERMINAL_STATES, ERROR_CATEGORIES, LIMITS } from '../domain/contracts.js';
import { bindSuppliedInputs, summarizeInputs, InputBindingError } from '../domain/input_binding.js';
import { loadExamples } from '../adapters/examples_store.js';
import * as store from '../adapters/persistence.js';
import { getEvidence, listEvidence, getReferenceBundle } from '../adapters/evidence.js';
import { enqueue, queueDepth, deadLetterQueue } from '../worker/queue.js';
import { TOKENS, PERMITTED_CONTEXT_ENVIRONMENTS, PERMITTED_CONTROL_ADAPTERS, PERMITTED_RUNNER_ADAPTERS, ALGORITHM_VERSION } from '../config.js';
import { uuid } from '../../../lib/digest.js';

function authenticate(ctx, requiredRole) {
  const header = ctx.headers.authorization ?? '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const principal = token ? TOKENS.get(token) : null;
  if (!principal) throw httpError('unauthorized', 'a valid workload token is required', 401);
  if (requiredRole && !principal.roles.includes(requiredRole)) {
    throw httpError('forbidden', `role "${requiredRole}" is required for this operation`, 403);
  }
  return principal;
}

const invalidInput = (message, details) => ({ status: 400, body: { error: { code: 'invalid-input', message, details } } });

export function registerRoutes(app) {
  app.get('/health', () => ({
    body: { status: 'ok', service: 'defense-validation-api', contract_id: 'defense-validation@1.0', algorithm_version: ALGORITHM_VERSION, queue: queueDepth() },
  }));

  /* ------------------------------------------------------- §9.1 submit */

  app.post('/v1/defense-validation-runs', (ctx) => {
    const principal = authenticate(ctx, 'submitter');

    const validation = validateSubmitRequest(ctx.body);
    if (!validation.valid) {
      return invalidInput('payload does not satisfy SubmitDefenseValidationRequest@1', validation.errors);
    }
    const request = ctx.body;

    let bound;
    try {
      bound = bindSuppliedInputs(request);
    } catch (error) {
      if (error instanceof InputBindingError) {
        return { status: 422, body: { error: { code: error.category, message: error.message, details: [{ field: error.field, message: error.message }] } } };
      }
      throw error;
    }

    // Adapter allowlist (§17): the payload may only name adapters this
    // deployment is configured to operate.
    if (!PERMITTED_CONTROL_ADAPTERS.includes(bound.context.candidate_application.adapter_id)) {
      return invalidInput('the named control adapter is not admitted by this deployment', [
        { field: 'validation_context.candidate_application.adapter_id', message: `must be one of: ${PERMITTED_CONTROL_ADAPTERS.join(', ')}` },
      ]);
    }
    if (!PERMITTED_RUNNER_ADAPTERS.includes(bound.context.execution.runner_adapter_id)) {
      return invalidInput('the named runner adapter is not admitted by this deployment', [
        { field: 'validation_context.execution.runner_adapter_id', message: `must be one of: ${PERMITTED_RUNNER_ADAPTERS.join(', ')}` },
      ]);
    }

    // Security boundary: production controls are unreachable from this service
    // (§4.3, §13.5). Rejected before a run exists — not a domain outcome.
    if (!PERMITTED_CONTEXT_ENVIRONMENTS.includes(bound.context.isolation.environment)) {
      store.audit(null, 'security.production-context-denied', { principal: principal.subject, validation_context_id: bound.context.validation_context_id });
      return {
        status: 403,
        body: { error: { code: 'production-context-denied', message: 'this capability may only address non-production validation contexts' } },
      };
    }

    const replay_key = store.computeReplayKey({ request, ...bound, algorithmVersion: ALGORITHM_VERSION });

    const existing = store.findRunByReplayKey(replay_key);
    if (existing && ctx.query.force !== 'true') {
      return {
        status: 200,
        body: {
          run_id: existing.run_id,
          result_id: existing.result_id,
          status: existing.terminal_state ? 'completed' : 'accepted',
          terminal_state: existing.terminal_state ?? null,
          deduplicated: true,
          replay_key,
          note: 'An identical payload has already been submitted. Re-submit with ?force=true to execute a fresh run.',
        },
      };
    }

    const run = store.createRun({
      result_id: `defense-validation-result:${uuid()}`,
      request,
      input_summary: summarizeInputs(bound),
      replay_key: ctx.query.force === 'true' ? `${replay_key}:${uuid().slice(0, 8)}` : replay_key,
      canonical_replay_key: replay_key,
      submitted_by: principal.subject,
      idempotency_key: ctx.headers['idempotency-key'] ?? null,
      trace_id: `trace-${uuid()}`,
    });
    store.audit(run.run_id, 'run.accepted', { principal: principal.subject, input_summary: run.input_summary });
    enqueue(run.run_id, bound.context.validation_context_id);

    return { status: 202, body: { run_id: run.run_id, result_id: run.result_id, status: 'accepted', replay_key, trace_id: run.trace_id } };
  });

  /**
   * Contract check without executing anything. Lets the console tell a caller
   * their payload is well-formed before they commit a run.
   */
  app.post('/v1/defense-validation-runs/validate', (ctx) => {
    authenticate(ctx, 'viewer');
    const validation = validateSubmitRequest(ctx.body);
    if (!validation.valid) return { status: 200, body: { valid: false, errors: validation.errors } };
    try {
      const bound = bindSuppliedInputs(ctx.body);
      return { status: 200, body: { valid: true, errors: [], derived_identities: summarizeInputs(bound) } };
    } catch (error) {
      return { status: 200, body: { valid: false, errors: [{ field: error.field ?? '', message: error.message }] } };
    }
  });

  /* --------------------------------------------------- §9.2 run status */

  app.get('/v1/defense-validation-runs', (ctx) => {
    authenticate(ctx, 'viewer');
    const runs = store.listRuns({ terminal_state: ctx.query.terminal_state, limit: Number(ctx.query.limit ?? 100) });
    return {
      body: {
        runs: runs.map((r) => ({
          run_id: r.run_id,
          result_id: r.result_id,
          state: r.state,
          terminal_state: r.terminal_state ?? null,
          proof_strength: r.proof_strength ?? null,
          created_at: r.created_at,
          completed_at: r.completed_at ?? null,
          submitted_by: r.submitted_by,
          input_summary: r.input_summary,
          finalized: Boolean(r.frozen),
          step_count: r.steps.length,
        })),
        queue: queueDepth(),
      },
    };
  });

  app.get('/v1/defense-validation-runs/:runId', (ctx) => {
    authenticate(ctx, 'viewer');
    const run = store.getRun(ctx.params.runId);
    if (!run) throw httpError('not-found', 'unknown run', 404);
    return {
      body: {
        run_id: run.run_id,
        result_id: run.result_id,
        state: run.state,
        terminal_state: run.terminal_state ?? null,
        proof_strength: run.proof_strength ?? null,
        // `terminal_state` means the verdict is decided and the result is
        // durable. `finalized` means the run has fully wound down, including
        // candidate removal — poll for this if you need the cleanup outcome.
        finalized: Boolean(run.frozen),
        created_at: run.created_at,
        updated_at: run.updated_at,
        completed_at: run.completed_at ?? null,
        trace_id: run.trace_id,
        submitted_by: run.submitted_by,
        replay_key: run.canonical_replay_key,
        reference_bundle_digest: run.reference_bundle_digest ?? null,
        cleanup_record: run.cleanup_record ?? null,
        input_summary: run.input_summary,
        request: run.request,
        steps: run.steps,
      },
    };
  });

  /* ------------------------------------------------ §9.3 immutable result */

  app.get('/v1/defense-validation-results/:resultId', async (ctx) => {
    authenticate(ctx, 'viewer');
    const result = await store.getResult(ctx.params.resultId);
    if (!result) throw httpError('not-found', 'unknown or not-yet-durable result', 404);
    return { body: result };
  });

  app.get('/v1/defense-validation-results/:resultId/reference-bundle', async (ctx) => {
    authenticate(ctx, 'viewer');
    const bundle = await getReferenceBundle(ctx.params.resultId);
    if (!bundle) throw httpError('not-found', 'unknown reference bundle', 404);
    return { body: bundle };
  });

  /* ---------------------------------------------------------- evidence */

  app.get('/v1/evidence/:digest', async (ctx) => {
    authenticate(ctx, 'viewer');
    const record = await getEvidence(ctx.params.digest);
    if (!record) throw httpError('not-found', 'unknown evidence object', 404);
    return { body: record };
  });

  app.get('/v1/evidence', async (ctx) => {
    authenticate(ctx, 'viewer');
    return { body: { evidence: await listEvidence(ctx.query.run_id) } };
  });

  /* ------------------------------------------ events, audit, observability */

  app.get('/v1/events', (ctx) => {
    authenticate(ctx, 'viewer');
    return { body: { events: store.listEvents({ limit: Number(ctx.query.limit ?? 100) }) } };
  });

  app.get('/v1/audit', (ctx) => {
    authenticate(ctx, 'viewer');
    return { body: { audit_events: store.listAudit(ctx.query.run_id).slice(-200).reverse() } };
  });

  app.get('/v1/metrics', async (ctx) => {
    authenticate(ctx, 'viewer');
    return { body: { ...(await store.metrics()), queue: queueDepth(), dead_letter: deadLetterQueue() } };
  });

  /* --------------------------------------------------- contract discovery */

  app.get('/v1/contract', () => ({
    body: {
      contract_id: 'defense-validation@1.0',
      note: 'Requests are self-contained. This service maintains no registry and resolves nothing by ID.',
      submit_request_schema: SUBMIT_REQUEST_SCHEMA,
      limits: LIMITS,
      admitted_control_adapters: PERMITTED_CONTROL_ADAPTERS,
      admitted_runner_adapters: PERMITTED_RUNNER_ADAPTERS,
      permitted_context_environments: PERMITTED_CONTEXT_ENVIRONMENTS,
      terminal_states: TERMINAL_STATES,
      error_categories: ERROR_CATEGORIES,
      completion_event_type: 'janus.defense-validation.completed.v1',
    },
  }));

  /**
   * Editable starting points for the request box. Not a registry: nothing here
   * is resolvable and the service never reads it during a run.
   */
  app.get('/v1/example-payloads', (ctx) => {
    authenticate(ctx, 'viewer');
    const { examples, directory, note } = loadExamples({ reload: ctx.query.reload === 'true' });
    return { body: { directory, note, examples } };
  });

  /* ------------------------------------------------------ result ledger */

  app.get('/v1/ledger', async (ctx) => {
    authenticate(ctx, 'viewer');
    const [stats, entries] = await Promise.all([
      store.ledgerStats(),
      store.listLedger({ terminal_state: ctx.query.terminal_state, limit: Number(ctx.query.limit ?? 200) }),
    ]);
    return { body: { ...stats, entries } };
  });
}
