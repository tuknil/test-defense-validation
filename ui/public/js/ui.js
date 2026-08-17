/** Small rendering helpers. Everything user-supplied goes through `esc`. */

export function esc(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

export const TERMINAL_STATES = [
  'validated',
  'failed-to-block',
  'unsafe',
  'environment-invalid',
  'inconclusive',
  'scope-declined',
  'malfunction',
];

export const STATE_MEANING = {
  validated: 'Required attacks blocked and required benign outcomes preserved in a valid context.',
  'failed-to-block': 'A required attack case still reached the protected target.',
  unsafe: 'A required benign case regressed with the candidate applied.',
  'environment-invalid': 'The context could not support a candidate judgment.',
  inconclusive: 'Required evidence was unresolved; no candidate claim is made.',
  'scope-declined': 'A valid request outside the configured coverage of the profile.',
  malfunction: 'No trustworthy domain result could be emitted. Diagnostics only.',
};

export function chip(state, { small = false } = {}) {
  if (!state) return '<span class="chip neutral plain">—</span>';
  return `<span class="chip${small ? ' sm' : ''}" data-state="${esc(state)}">${esc(state)}</span>`;
}

export function conclusionChip(conclusion) {
  const map = {
    'blocked-as-required': 'validated',
    preserved: 'validated',
    'not-blocked': 'failed-to-block',
    regressed: 'unsafe',
    undetermined: 'inconclusive',
  };
  return `<span class="chip sm" data-state="${map[conclusion] ?? 'malfunction'}">${esc(conclusion)}</span>`;
}

export function shortId(value, keep = 10) {
  if (!value) return '—';
  const text = String(value);
  if (text.startsWith('sha256:')) return `${text.slice(0, 7 + keep)}…`;
  return text.length > 46 ? `${text.slice(0, 46)}…` : text;
}

export function timeAgo(iso) {
  if (!iso) return '—';
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return `${Math.floor(seconds)}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return new Date(iso).toLocaleDateString();
}

export function json(value) {
  const text = JSON.stringify(value, null, 2) ?? 'null';
  return esc(text)
    .replace(/(&quot;(?:[^&]|&(?!quot;))*?&quot;)(\s*:)/g, '<span class="tok-key">$1</span>$2')
    .replace(/:\s*(&quot;(?:[^&]|&(?!quot;))*?&quot;)/g, ': <span class="tok-str">$1</span>')
    .replace(/:\s*(-?\d+\.?\d*)/g, ': <span class="tok-num">$1</span>')
    .replace(/:\s*(true|false)/g, ': <span class="tok-bool">$1</span>')
    .replace(/:\s*(null)/g, ': <span class="tok-null">$1</span>');
}

export function jsonBlock(title, value, { open = false } = {}) {
  return `<details class="json"${open ? ' open' : ''}>
    <summary>${esc(title)}</summary>
    <pre class="code">${json(value)}</pre>
  </details>`;
}

export function card(title, bodyHtml, { subtitle = '', aside = '' } = {}) {
  return `<section class="card">
    <div class="card-head">
      <div>
        <h3>${esc(title)}</h3>
        ${subtitle ? `<p class="card-sub">${esc(subtitle)}</p>` : ''}
      </div>
      ${aside ? `<div class="row">${aside}</div>` : ''}
    </div>
    ${bodyHtml}
  </section>`;
}

export function empty(message) {
  return `<div class="empty">${esc(message)}</div>`;
}

export function pageHead(title, description) {
  return `<header class="page-head"><h1>${esc(title)}</h1><p>${esc(description)}</p></header>`;
}
