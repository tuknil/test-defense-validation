import { api } from '../api.js';
import { esc, chip, card, pageHead } from '../ui.js';
import { renderPipeline, renderResult, wireEvidence } from './result.js';

/**
 * The whole console, on one page: one request in, one result out.
 * Submitting never navigates away — the pipeline and then the result appear
 * beneath the request that produced them.
 */
export async function renderValidate(main) {
  const { examples, directory } = await api.examples();

  main.innerHTML = `
    ${pageHead('Validate', 'Submit one request payload. The result appears below it and is written to the ledger.')}

    ${card(
      'Request',
      `<div class="row" style="margin-bottom:10px">
        <label class="field-label" for="example" style="margin:0">Start from</label>
        <select class="select" id="example" style="max-width:420px">
          <option value="">— blank / keep current —</option>
          ${examples.map((e) => `<option value="${esc(e.id)}">${esc(e.id)} · ${esc(e.title)}</option>`).join('')}
        </select>
        <span class="field-hint mono" style="margin-left:auto" title="${esc(directory)}">${esc(examples.length)} example(s) in ${esc(directory.split('/').pop())}/</span>
      </div>
      <div id="example-note"></div>

      <textarea id="payload" class="payload-box mono" spellcheck="false" aria-label="Request payload JSON"></textarea>

      <div class="row" style="margin-top:12px">
        <button class="btn primary" id="submit">Submit</button>
        <button class="btn" id="format">Format</button>
        <button class="btn" id="check">Check contract</button>
        <span id="parse-state" class="field-hint" style="margin-left:auto"></span>
      </div>
      <div id="feedback" style="margin-top:14px"></div>`,
      { subtitle: 'SubmitDefenseValidationRequest@1 — candidate artifact, both suites, context, profile, and policy, all inline.' },
    )}

    <div id="outcome"></div>
  `;

  const box = main.querySelector('#payload');
  const parseState = main.querySelector('#parse-state');
  const feedback = main.querySelector('#feedback');
  const outcome = main.querySelector('#outcome');

  box.value = sessionStorage.getItem('dv.draft') ?? JSON.stringify(examples[0]?.request ?? {}, null, 2);

  const parse = () => {
    try {
      const value = JSON.parse(box.value);
      parseState.textContent = `valid JSON · ${box.value.length.toLocaleString()} chars`;
      parseState.style.color = '';
      return value;
    } catch (error) {
      parseState.textContent = `JSON syntax error: ${error.message}`;
      parseState.style.color = 'var(--unsafe)';
      return null;
    }
  };
  box.addEventListener('input', () => {
    sessionStorage.setItem('dv.draft', box.value);
    parse();
  });
  parse();

  main.querySelector('#example').addEventListener('change', (event) => {
    const example = examples.find((e) => e.id === event.target.value);
    if (!example) return;
    box.value = JSON.stringify(example.request, null, 2);
    sessionStorage.setItem('dv.draft', box.value);
    parse();
    feedback.innerHTML = '';
    outcome.innerHTML = '';
    main.querySelector('#example-note').innerHTML = `<div class="banner" data-tone="info" style="margin-bottom:10px"><div>
      <div class="banner-title">${esc(example.id)} — ${esc(example.title)} ${example.expected.rejected ? '' : chip(example.expected.terminal_state, { small: true })}</div>
      <div class="banner-body">${esc(example.narrative)} Edit anything below before submitting.</div>
    </div></div>`;
  });

  main.querySelector('#format').addEventListener('click', () => {
    const value = parse();
    if (!value) return;
    box.value = JSON.stringify(value, null, 2);
    sessionStorage.setItem('dv.draft', box.value);
    parse();
  });

  const showErrors = (title, errors) => {
    feedback.innerHTML = `<div class="banner" data-tone="error"><div style="min-width:0">
      <div class="banner-title">${esc(title)}</div>
      ${
        errors?.length
          ? `<div class="table-wrap" style="margin-top:8px"><table>
              <thead><tr><th>Field</th><th>Problem</th></tr></thead>
              <tbody>${errors.map((e) => `<tr><td class="mono">${esc(e.field || '(root)')}</td><td class="muted">${esc(e.message)}</td></tr>`).join('')}</tbody>
            </table></div>`
          : ''
      }
    </div></div>`;
  };

  main.querySelector('#check').addEventListener('click', async () => {
    const value = parse();
    if (!value) return showErrors('The payload is not valid JSON', []);
    const check = await api.validate(value);
    if (check.valid) {
      feedback.innerHTML = `<div class="banner" data-tone="info"><div>
        <div class="banner-title">Payload satisfies the contract</div>
        <dl class="kv" style="margin-top:8px">
          ${Object.entries(check.derived_identities).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}
        </dl>
      </div></div>`;
    } else {
      showErrors(`${check.errors.length} contract violation(s)`, check.errors);
    }
  });

  main.querySelector('#submit').addEventListener('click', async () => {
    const value = parse();
    if (!value) return showErrors('The payload is not valid JSON — fix the syntax error before submitting', []);

    feedback.innerHTML = '';
    outcome.innerHTML = '<div class="empty"><span class="spinner"></span></div>';

    let submitted;
    try {
      submitted = await api.submit(value, { force: true });
    } catch (error) {
      outcome.innerHTML = '';
      return showErrors(`${error.code ?? 'rejected'} (HTTP ${error.status ?? '—'}) — ${error.message}`, error.details);
    }

    // Poll the run, redrawing the pipeline until it reaches a terminal state.
    for (;;) {
      const run = await api.run(submitted.run_id);
      // `finalized` rather than `terminal_state`, so the rendered pipeline
      // includes the persist and candidate-removal steps.
      if (run.finalized) {
        const result = await api.result(run.result_id);
        outcome.innerHTML = `<h2 class="section">Pipeline</h2>${renderPipeline(run)}${renderResult(result, { run })}`;
        wireEvidence(outcome);
        outcome.querySelector('.section')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        return;
      }
      outcome.innerHTML = `<h2 class="section">Pipeline</h2>${renderPipeline(run)}`;
      await new Promise((resolve) => setTimeout(resolve, 450));
    }
  });
}
