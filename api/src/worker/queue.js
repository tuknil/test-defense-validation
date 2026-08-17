/**
 * In-process work queue standing in for Service Bus (§3.3, §4.2).
 *
 * Preserves the properties the design depends on: bounded concurrency, at most
 * one mutation in flight per validation context (§15.2), bounded transient
 * retries, and a dead-letter queue.
 */
import * as store from '../adapters/persistence.js';
import { executeRun } from './worker.js';

const MAX_CONCURRENCY = Number(process.env.WORKER_CONCURRENCY ?? 4);
const MAX_RETRIES = Number(process.env.WORKER_MAX_RETRIES ?? 3);

const pending = [];
const deadLetter = [];
const activeContexts = new Set();
let running = 0;

export function enqueue(runId, contextId) {
  pending.push({ runId, contextId, attempts: 0, enqueued_at: Date.now() });
  store.audit(runId, 'run.enqueued', { context_id: contextId });
  setImmediate(pump);
}

function pump() {
  while (running < MAX_CONCURRENCY) {
    // Serialize per validation context: at most one candidate mutation at a time.
    const index = pending.findIndex((job) => !activeContexts.has(job.contextId));
    if (index === -1) return;
    const [job] = pending.splice(index, 1);
    activeContexts.add(job.contextId);
    running += 1;
    void run(job);
  }
}

async function run(job) {
  try {
    await executeRun(job.runId);
  } catch (err) {
    job.attempts += 1;
    if (job.attempts <= MAX_RETRIES) {
      store.audit(job.runId, 'run.retry', { attempt: job.attempts, error: err.message });
      pending.push(job);
    } else {
      deadLetter.push({ ...job, error: err.message, dead_lettered_at: new Date().toISOString() });
      store.audit(job.runId, 'run.dead-lettered', { error: err.message });
    }
  } finally {
    running -= 1;
    activeContexts.delete(job.contextId);
    setImmediate(pump);
  }
}

export function queueDepth() {
  return { pending: pending.length, running, dead_letter: deadLetter.length, active_contexts: [...activeContexts] };
}

export function deadLetterQueue() {
  return [...deadLetter];
}
