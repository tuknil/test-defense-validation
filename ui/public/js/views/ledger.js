import { api } from '../api.js';
import { esc, chip, card, pageHead, empty, timeAgo, TERMINAL_STATES } from '../ui.js';
import { renderResult, wireEvidence } from './result.js';

/** The append-only record of every result this deployment has produced. */
export async function renderLedger(main) {
  main.innerHTML = `${pageHead('Ledger', 'Every result, append-only and durable.')}<div class="empty"><span class="spinner"></span></div>`;

  let filter = '';

  const draw = async () => {
    const ledger = await api.ledger(filter ? `?terminal_state=${encodeURIComponent(filter)}` : '');
    const distribution = ledger.terminal_state_distribution ?? {};
    const total = Object.values(distribution).reduce((a, b) => a + b, 0);

    main.innerHTML = `
      ${pageHead('Ledger', 'Every result this deployment has produced, append-only and durable across restarts.')}

      ${
        total
          ? `<div class="card" style="margin-bottom:14px">
              <div class="bar">${TERMINAL_STATES.filter((s) => distribution[s])
                .map((s) => `<span style="width:${((distribution[s] / total) * 100).toFixed(2)}%;background:var(--${s})" title="${esc(s)}: ${distribution[s]}"></span>`)
                .join('')}</div>
              <div class="legend">${TERMINAL_STATES.filter((s) => distribution[s])
                .map((s) => `<span class="legend-item"><span class="legend-swatch" style="background:var(--${s})"></span>${esc(s)} · ${distribution[s]}</span>`)
                .join('')}</div>
            </div>`
          : ''
      }

      <div class="row" style="margin-bottom:14px">
        <button class="btn sm${filter === '' ? ' primary' : ''}" data-filter="">All ${total ? `· ${total}` : ''}</button>
        ${TERMINAL_STATES.filter((s) => distribution[s]).map((s) => `<button class="btn sm${filter === s ? ' primary' : ''}" data-filter="${esc(s)}">${esc(s)} · ${distribution[s]}</button>`).join('')}
      </div>

      ${card(
        `${ledger.entries.length} entr${ledger.entries.length === 1 ? 'y' : 'ies'}`,
        ledger.entries.length
          ? `<div class="table-wrap"><table>
              <thead><tr><th>State</th><th>Candidate</th><th>Context</th><th>Proof</th><th>Attack</th><th>Benign</th><th class="right">Recorded</th></tr></thead>
              <tbody>${ledger.entries
                .map(
                  (e) => `<tr class="clickable" data-result="${esc(e.result_id)}">
                    <td>${chip(e.terminal_state)}</td>
                    <td class="stack">
                      <span class="mono">${esc((e.control_candidate_id ?? '—').replace('control-candidate:', ''))}</span>
                      <span class="faint mono" style="font-size:10.5px">${esc((e.candidate_digest ?? '').slice(0, 20))}…</span>
                    </td>
                    <td class="mono faint">${esc((e.validation_context_id ?? '—').replace('validation-context:', ''))}</td>
                    <td class="mono faint">${esc(e.proof_strength ?? '—')}</td>
                    <td class="mono faint">${esc(e.attack_blocked)}/${esc(e.attack_cases)}</td>
                    <td class="mono faint">${esc(e.benign_preserved)}/${esc(e.benign_cases)}</td>
                    <td class="right faint nowrap">${esc(timeAgo(e.recorded_at))}</td>
                  </tr>`,
                )
                .join('')}</tbody></table></div>`
          : empty('No results recorded yet. Submit a request from the Validate page.'),
        { subtitle: 'Entries are appended, never rewritten. Attack and benign columns count required cases only.' },
      )}

      <div id="ledger-detail"></div>
    `;

    main.querySelectorAll('[data-filter]').forEach((button) =>
      button.addEventListener('click', () => {
        filter = button.dataset.filter;
        void draw();
      }),
    );

    main.querySelectorAll('[data-result]').forEach((row) =>
      row.addEventListener('click', async () => {
        const detail = main.querySelector('#ledger-detail');
        detail.innerHTML = '<div class="empty"><span class="spinner"></span></div>';
        try {
          const result = await api.result(row.dataset.result);
          detail.innerHTML = renderResult(result);
          wireEvidence(detail);
          detail.scrollIntoView({ behavior: 'smooth', block: 'start' });
        } catch (error) {
          detail.innerHTML = `<div class="banner" data-tone="error"><div class="banner-body">${esc(error.message)}</div></div>`;
        }
      }),
    );
  };

  await draw();
}
