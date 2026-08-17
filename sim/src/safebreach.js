/**
 * Simulated SafeBreach-style BAS vendor API.
 *
 * Deliberately vendor-shaped and *not* in the capability's normalized vocabulary:
 * it speaks "scenarios", "simulators", "verdicts" and "steps". Mapping that onto
 * normalized observations is the runner adapter's job, which keeps the vendor
 * boundary honest and swappable.
 */
import { getInstance, sendTraffic } from './waf.js';
import { uuid, nowIso } from '../../lib/digest.js';

const executions = new Map();
const LATENCY_MS = Number(process.env.SIM_LATENCY_MS ?? 120);

export function createExecution({ scenario_id, simulator_id, instance_id, case_id, request }) {
  const instance = getInstance(instance_id);
  if (!instance) return { ok: false, error: { code: 'simulator-target-unknown', message: `unknown instance ${instance_id}` } };

  const execution_id = `sbx-${uuid().slice(0, 12)}`;
  const started_at = nowIso();

  // Traffic is generated immediately; only the vendor's *reporting* is delayed,
  // which is what forces the adapter to poll like a real BAS integration.
  const transaction = sendTraffic(instance, request);

  const record = {
    execution_id,
    scenario_id,
    simulator_id: simulator_id ?? 'sim-nonprod-01',
    instance_id,
    case_id,
    started_at,
    ready_at: Date.now() + LATENCY_MS,
    transaction,
  };
  executions.set(execution_id, record);
  return { ok: true, execution: { execution_id, scenario_id, simulator_id: record.simulator_id, status: 'running', started_at } };
}

export function getExecution(execution_id) {
  const record = executions.get(execution_id);
  if (!record) return null;

  if (Date.now() < record.ready_at) {
    return {
      execution_id: record.execution_id,
      scenario_id: record.scenario_id,
      simulator_id: record.simulator_id,
      status: 'running',
      started_at: record.started_at,
    };
  }

  const { control, target } = record.transaction;
  let verdict = 'undetermined';
  if (control.decision === 'deny') verdict = 'prevented';
  else if (target?.reached) verdict = 'delivered';

  return {
    execution_id: record.execution_id,
    scenario_id: record.scenario_id,
    simulator_id: record.simulator_id,
    status: 'completed',
    started_at: record.started_at,
    ended_at: nowIso(),
    verdict,
    steps: [
      {
        step_id: 1,
        action: 'http-request',
        case_id: record.case_id,
        transaction: record.transaction,
      },
    ],
    // Vendor responses routinely carry credentials; redaction is downstream.
    simulator_api_key: 'sk-sim-live-9d2f41c0a77b4e18',
  };
}

export function listExecutions(limit = 50) {
  return [...executions.values()]
    .slice(-limit)
    .reverse()
    .map((r) => ({ execution_id: r.execution_id, scenario_id: r.scenario_id, case_id: r.case_id, instance_id: r.instance_id, started_at: r.started_at }));
}
