import { createApp } from '../lib/microhttp.js';
import { registerRoutes } from './src/http/routes.js';
import { loadExamples } from './src/adapters/examples_store.js';
import { initDatabase, selectLedgerStats, DB_DIR } from './src/adapters/db.js';
import { PORT, CONTROL_PLANE_BASE_URL, SAFEBREACH_BASE_URL } from './src/config.js';

const app = createApp({ name: 'api' });
registerRoutes(app);

await initDatabase();
const { total } = await selectLedgerStats();
const { examples } = loadExamples();

app.listen(PORT).then(() => {
  // eslint-disable-next-line no-console
  console.log(`[api]  defense-validation API on http://localhost:${PORT}`);
  // eslint-disable-next-line no-console
  console.log(`[api]  control plane -> ${CONTROL_PLANE_BASE_URL}   safebreach -> ${SAFEBREACH_BASE_URL}`);
  // eslint-disable-next-line no-console
  console.log(`[api]  embedded postgres ${DB_DIR} (${total} result(s) on record) · ${examples.length} example payload(s)`);
});
