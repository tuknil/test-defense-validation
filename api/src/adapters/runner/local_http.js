/**
 * TestExecutionAdapter: direct HTTP runner (§6.5).
 *
 * Only admitted case material is executed, and only against the validation
 * ingress declared by the bound context. No arbitrary URLs, no shell, no
 * case-supplied targets (§13.4).
 */
import { CONTROL_PLANE_BASE_URL } from '../../config.js';
import { AdapterError } from '../control/modsecurity.js';

export const localHttpRunner = {
  adapter_id: 'runner-adapter-local-http:1',

  async execute(context, testCase, trial) {
    const { instance_id } = context.candidate_application;
    const request = admitRequest(testCase.request);
    let response;
    try {
      response = await fetch(`${CONTROL_PLANE_BASE_URL}/waf/v1/instances/${instance_id}/traffic`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      });
    } catch (err) {
      throw new AdapterError('runner-failure', `validation ingress unreachable: ${err.message}`);
    }
    const body = await response.json();
    if (!response.ok) throw new AdapterError('runner-failure', body?.error?.message ?? 'traffic execution failed');

    return {
      runner: this.adapter_id,
      case_id: testCase.case_id,
      trial,
      execution_ref: body.transaction_id,
      vendor_payload: null,
      transactions: [body],
    };
  },
};

/**
 * Case material is untrusted. Only typed, allowlisted fields are interpreted,
 * and the path must stay relative to the declared ingress.
 */
export function admitRequest(request) {
  const method = String(request.method ?? 'GET').toUpperCase();
  if (!['GET', 'POST', 'PUT', 'DELETE', 'HEAD'].includes(method)) {
    throw new AdapterError('runner-failure', `case declares an unsupported method "${method}"`);
  }
  const path = String(request.path ?? '/');
  if (!path.startsWith('/') || path.startsWith('//') || path.includes('..')) {
    throw new AdapterError('runner-failure', 'case declares a target outside the declared validation ingress');
  }
  return {
    method,
    path,
    query: request.query ? String(request.query) : null,
    headers: {},
    body: request.body ? String(request.body) : null,
  };
}
