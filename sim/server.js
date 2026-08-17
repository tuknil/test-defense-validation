/**
 * External execution plane simulator (LLD §3.2 "External execution").
 *
 * Hosts two independent vendor surfaces that the defense-validation service
 * reaches only over HTTP:
 *   /waf/v1/...        dev-equivalent control + protected non-prod target
 *   /safebreach/v1/... BAS scenario execution API
 *
 * Nothing in here knows about terminal states, proof strength, or policy.
 */
import { createApp, httpError } from '../lib/microhttp.js';
import { listInstances, getInstance, describeInstance, applyCandidate, removeApplication, policyState, sendTraffic, resetInstances } from './src/waf.js';
import { createExecution, getExecution, listExecutions } from './src/safebreach.js';

const PORT = Number(process.env.SIM_PORT ?? 8099);
const app = createApp({ name: 'sim' });

const requireInstance = (id) => {
  const instance = getInstance(id);
  if (!instance) throw httpError('instance-not-found', `unknown control instance ${id}`, 404);
  return instance;
};

app.get('/health', () => ({ body: { status: 'ok', service: 'external-execution-simulator', instances: listInstances().length } }));

/* ---------------------------------------------------------------- control */

app.get('/waf/v1/instances', () => ({ body: { instances: listInstances() } }));

app.get('/waf/v1/instances/:instanceId', (ctx) => ({ body: describeInstance(requireInstance(ctx.params.instanceId)) }));

app.get('/waf/v1/instances/:instanceId/policies/:policyRef', (ctx) => ({
  body: policyState(requireInstance(ctx.params.instanceId), ctx.params.policyRef),
}));

app.post('/waf/v1/instances/:instanceId/policies/:policyRef/rules', (ctx) => {
  const instance = requireInstance(ctx.params.instanceId);
  const { candidate_id, candidate_digest, artifact } = ctx.body ?? {};
  if (!candidate_id || !candidate_digest || !artifact) {
    throw httpError('invalid-input', 'candidate_id, candidate_digest and artifact are required', 400);
  }
  const result = applyCandidate(instance, { policy_ref: ctx.params.policyRef, candidate_id, candidate_digest, artifact });
  if (!result.ok) {
    return { status: result.error.code === 'apply-indeterminate' ? 503 : 422, body: { error: result.error } };
  }
  return {
    status: 201,
    body: {
      application_id: result.application.application_id,
      instance_id: instance.instance_id,
      policy_ref: ctx.params.policyRef,
      candidate_id,
      candidate_digest,
      applied_rule_ids: result.application.rules.map((r) => r.rule_id),
      applied_at: result.application.applied_at,
      control_state: result.control_state,
    },
  };
});

app.del('/waf/v1/instances/:instanceId/applications/:applicationId', (ctx) => {
  const instance = requireInstance(ctx.params.instanceId);
  const result = removeApplication(instance, ctx.params.applicationId);
  if (!result.ok) return { status: 409, body: { error: result.error } };
  return { body: result.reset_evidence };
});

app.post('/waf/v1/instances/:instanceId/traffic', (ctx) => {
  const instance = requireInstance(ctx.params.instanceId);
  const { method = 'GET', path = '/', query = null, headers = {}, body = null } = ctx.body ?? {};
  if (!String(path).startsWith('/')) throw httpError('invalid-input', 'path must be relative to the declared validation ingress', 400);
  return { body: sendTraffic(instance, { method, path, query, headers, body }) };
});

app.get('/waf/v1/instances/:instanceId/transactions', (ctx) => {
  const instance = requireInstance(ctx.params.instanceId);
  return { body: { transactions: instance.transactions.slice(-50).reverse() } };
});

/* ------------------------------------------------------------ safebreach */

app.post('/safebreach/v1/executions', (ctx) => {
  const { scenario_id, simulator_id, instance_id, case_id, request } = ctx.body ?? {};
  if (!scenario_id || !instance_id || !request) throw httpError('invalid-input', 'scenario_id, instance_id and request are required', 400);
  const result = createExecution({ scenario_id, simulator_id, instance_id, case_id, request });
  if (!result.ok) return { status: 422, body: { error: result.error } };
  return { status: 202, body: result.execution };
});

app.get('/safebreach/v1/executions/:executionId', (ctx) => {
  const execution = getExecution(ctx.params.executionId);
  if (!execution) throw httpError('execution-not-found', 'unknown execution', 404);
  return { body: execution };
});

app.get('/safebreach/v1/executions', () => ({ body: { executions: listExecutions() } }));

/* ------------------------------------------------------------ lab control */

app.post('/admin/v1/reset', () => {
  resetInstances();
  return { body: { status: 'reset', instances: listInstances().length } };
});

export const server = await app.listen(PORT);
// eslint-disable-next-line no-console
console.log(`[sim]  external execution simulator (WAF + target + SafeBreach) on http://localhost:${PORT}`);
