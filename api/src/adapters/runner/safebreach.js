/**
 * TestExecutionAdapter: SafeBreach/BAS connector (§6.5, ADR-003).
 *
 * Talks to the vendor's scenario-execution API and polls for completion. It
 * carries no control-policy mutation rights — candidate application is the
 * control adapter's job and stays separate.
 *
 * The vendor endpoint is currently the local simulator; point SAFEBREACH_BASE_URL
 * at a real tenant and nothing else in the service changes.
 */
import { SAFEBREACH_BASE_URL, SAFEBREACH_POLL_INTERVAL_MS, SAFEBREACH_TIMEOUT_MS } from '../../config.js';
import { AdapterError } from '../control/modsecurity.js';
import { admitRequest } from './local_http.js';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export const safebreachRunner = {
  adapter_id: 'runner-adapter-safebreach:1',

  async execute(context, testCase, trial) {
    const { instance_id } = context.candidate_application;
    const scenario_id = `${context.execution.scenario_prefix ?? 'janus-dv'}:${testCase.case_id}:${trial}`;
    const request = admitRequest(testCase.request);

    const created = await vendorCall('/safebreach/v1/executions', {
      method: 'POST',
      body: JSON.stringify({
        scenario_id,
        simulator_id: context.execution.simulator_id,
        instance_id,
        case_id: testCase.case_id,
        request,
      }),
    });

    const deadline = Date.now() + SAFEBREACH_TIMEOUT_MS;
    let execution = null;
    while (Date.now() < deadline) {
      execution = await vendorCall(`/safebreach/v1/executions/${created.execution_id}`);
      if (execution.status === 'completed') break;
      await sleep(SAFEBREACH_POLL_INTERVAL_MS);
    }
    if (!execution || execution.status !== 'completed') {
      throw new AdapterError('runner-failure', `simulator execution ${created.execution_id} did not complete within the configured timeout`);
    }

    return {
      runner: this.adapter_id,
      case_id: testCase.case_id,
      trial,
      execution_ref: execution.execution_id,
      vendor_verdict: execution.verdict,
      vendor_payload: execution,
      transactions: execution.steps.map((step) => step.transaction),
    };
  },
};

async function vendorCall(path, init = {}) {
  let response;
  try {
    response = await fetch(`${SAFEBREACH_BASE_URL}${path}`, {
      ...init,
      headers: {
        'Content-Type': 'application/json',
        // Sourced from Key Vault in a real deployment (§4.3).
        Authorization: 'Bearer sb-nonprod-tenant-token',
        ...(init.headers ?? {}),
      },
    });
  } catch (err) {
    throw new AdapterError('runner-failure', `simulator API unreachable: ${err.message}`);
  }
  const body = await response.json().catch(() => null);
  if (!response.ok) throw new AdapterError('runner-failure', body?.error?.message ?? `simulator API returned ${response.status}`);
  return body;
}
