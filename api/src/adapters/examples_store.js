/**
 * Reads example payloads from the `examples/` directory on disk.
 *
 * These are editable starting points for the request box, nothing more. The
 * service never consults them during a run — a validation binds only to the
 * material in the submitted payload. Each file is a complete, directly
 * submittable request:
 *
 *   curl -X POST localhost:8088/v1/defense-validation-runs \
 *        -H 'Authorization: Bearer dev-submitter-token' \
 *        -H 'Content-Type: application/json' \
 *        -d @examples/conf-01-validated.json
 */
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const EXAMPLES_DIR = process.env.EXAMPLES_DIR ?? path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../examples');

let cache = null;

export function loadExamples({ reload = false } = {}) {
  if (cache && !reload) return cache;

  const indexPath = path.join(EXAMPLES_DIR, 'index.json');
  if (!existsSync(indexPath)) {
    // Examples are a convenience, never a dependency. A missing directory is
    // not a reason for the capability to fail to start.
    cache = { directory: EXAMPLES_DIR, note: 'no examples directory found', examples: [] };
    return cache;
  }

  const index = JSON.parse(readFileSync(indexPath, 'utf8'));
  const examples = [];
  for (const entry of index.examples ?? []) {
    const file = path.join(EXAMPLES_DIR, path.basename(entry.file));
    if (!existsSync(file)) continue;
    try {
      examples.push({ ...entry, request: JSON.parse(readFileSync(file, 'utf8')) });
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(`[api] example ${entry.file} is not valid JSON: ${err.message}`);
    }
  }

  cache = { directory: EXAMPLES_DIR, note: index.note ?? null, examples };
  return cache;
}
