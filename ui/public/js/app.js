import { api, simHealth, IDENTITIES, currentToken, setToken } from './api.js';
import { esc } from './ui.js';
import { renderValidate } from './views/validate.js';
import { renderLedger } from './views/ledger.js';

const main = document.getElementById('main');
const nav = document.getElementById('nav');

async function route() {
  const section = (window.location.hash.replace('#/', '').split('/')[0]) || 'validate';
  nav.querySelectorAll('a').forEach((a) => a.classList.toggle('active', a.dataset.route === section));

  try {
    if (section === 'ledger') await renderLedger(main);
    else await renderValidate(main);
  } catch (error) {
    main.innerHTML = `<div class="banner" data-tone="error"><div>
      <div class="banner-title">${esc(error.code ?? 'request failed')}${error.status ? ` (HTTP ${esc(error.status)})` : ''}</div>
      <div class="banner-body">${esc(error.message)}</div>
      <div class="banner-body" style="margin-top:8px">API base: <span class="mono">${esc(api.baseUrl)}</span> — check that the API and simulator are running (<span class="mono">npm run dev</span>).</div>
    </div></div>`;
  }
}

/* Workload identity switcher — makes the API's RBAC observable. */
const roleSelect = document.getElementById('role');
roleSelect.innerHTML = IDENTITIES.map((i) => `<option value="${esc(i.token)}"${i.token === currentToken() ? ' selected' : ''}>${esc(i.label)}</option>`).join('');
roleSelect.addEventListener('change', (event) => {
  setToken(event.target.value);
  route();
});

/* Theme toggle. Dark is the default; the choice persists per browser. */
const themeButton = document.getElementById('theme');
function paintThemeButton() {
  const isLight = document.documentElement.dataset.theme === 'light';
  document.getElementById('theme-icon').textContent = isLight ? '◑' : '◐';
  document.getElementById('theme-label').textContent = isLight ? 'Dark mode' : 'Light mode';
  themeButton.setAttribute('aria-pressed', String(isLight));
}
themeButton.addEventListener('click', () => {
  const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
  document.documentElement.dataset.theme = next;
  localStorage.setItem('dv.theme', next);
  paintThemeButton();
});
paintThemeButton();

async function pollHealth() {
  const target = document.getElementById('health');
  const rows = [];
  try {
    const health = await api.health();
    rows.push({ up: true, label: `api · ${health.queue.running} running` });
  } catch {
    rows.push({ up: false, label: 'api · unreachable' });
  }
  try {
    const sim = await simHealth();
    rows.push({ up: true, label: `sim · ${sim.instances} contexts` });
  } catch {
    rows.push({ up: false, label: 'sim · unreachable' });
  }
  target.innerHTML = rows.map((r) => `<div class="health-row"><span class="dot ${r.up ? 'up' : 'down'}"></span>${esc(r.label)}</div>`).join('');
  setTimeout(pollHealth, 5000);
}

window.addEventListener('hashchange', route);
void route();
void pollHealth();
