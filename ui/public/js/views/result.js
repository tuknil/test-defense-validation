/**
 * Result rendering, shared by the validate page (live) and the ledger (stored).
 */
import { api } from '../api.js';
import { esc, chip, conclusionChip, card, jsonBlock, empty, STATE_MEANING } from '../ui.js';

export function renderPipeline(run) {
  const steps = [...run.steps].sort((a, b) => a.seq - b.seq || a.started_at.localeCompare(b.started_at));
  return card(
    run.terminal_state ? 'Pipeline complete' : 'Executing…',
    steps.length
      ? `<div class="pipeline">${steps
          .map(
            (s) => `<div class="pstep" data-status="${esc(s.status)}">
              <div class="pstep-marker">${s.status === 'ok' ? '✓' : s.status === 'skipped' ? '–' : s.status === 'failed' || s.status === 'failed-domain' ? '✕' : esc(s.seq)}</div>
              <div>
                <div class="pstep-name">${esc(s.name)}</div>
                ${s.detail ? `<div class="pstep-detail">${esc(s.detail)}</div>` : ''}
              </div>
              <div class="pstep-time">${s.duration_ms === null ? '<span class="spinner"></span>' : `${esc(s.duration_ms)} ms`}</div>
            </div>`,
          )
          .join('')}</div>`
      : empty('Waiting for the worker to pick up this run…'),
    { subtitle: 'Context validity is established before any candidate judgment; the candidate is removed and evidenced on the way out.' },
  );
}

export function renderResult(result, { run = null } = {}) {
  return `
    ${verdict(result)}
    ${precedence(result)}
    ${contextCard(result)}
    ${candidateCard(result, run)}
    ${attackTable(result)}
    ${benignTable(result)}
    ${limitations(result)}
    ${evidenceCard(result)}
    <h2 class="section">Raw records</h2>
    ${jsonBlock('DefenseValidationResult@1 (immutable, ledger entry)', result)}
  `;
}

function verdict(result) {
  const diagnostics = result.diagnostics
    ? `<div class="banner" data-tone="error" style="margin-top:12px"><div>
        <div class="banner-title">${esc(result.diagnostics.category)}</div>
        <div class="banner-body">${esc(result.diagnostics.message)}${result.diagnostics.candidate_state_known === false ? ' — actual control state is unknown; reconciliation is required before any retry.' : ''}</div>
      </div></div>`
    : '';
  return `
    <h2 class="section">Result</h2>
    ${card(
      result.terminal_state,
      `<p class="muted" style="margin-top:0">${esc(result.prose_summary)}</p>
       <dl class="kv" style="margin-top:14px">
         <dt>Result ID</dt><dd>${esc(result.result_id)}</dd>
         <dt>Decided by</dt><dd>rule ${esc(result.decided_by.rule ?? '—')} · ${esc(result.decided_by.name)}</dd>
         <dt>Reason</dt><dd style="font-family:var(--sans);font-size:12.8px">${esc(result.decided_by.reason)}</dd>
         <dt>Proof strength</dt><dd>${esc(result.proof_strength)}</dd>
         <dt>Candidate</dt><dd>${esc(result.subject.control_candidate_id ?? '—')}</dd>
         <dt>Candidate digest</dt><dd>${esc(result.subject.candidate_digest ?? '—')}</dd>
         <dt>Context</dt><dd>${esc(result.input_bindings.validation_context_id ?? '—')}</dd>
       </dl>
       ${diagnostics}
       <p class="field-hint" style="margin-top:14px">The prose summary is rendered from structured fields and is non-authoritative.</p>`,
      { subtitle: STATE_MEANING[result.terminal_state] },
    )}`;
}

function precedence(result) {
  return `
    <h2 class="section">Terminal-state precedence</h2>
    ${card(
      'Ordered rule evaluation',
      result.precedence_trace
        .map(
          (r) => `<div class="rule ${r.fired ? 'fired met' : r.condition_met ? 'met' : 'unmet'}">
            <div class="rule-num">${esc(r.rule)}</div>
            <div>
              <div class="rule-name">${esc(r.name)} ${chip(r.terminal_state, { small: true })}</div>
              ${r.reason ? `<div class="rule-reason">${esc(r.reason)}</div>` : '<div class="rule-reason faint">condition not met</div>'}
            </div>
            <div class="mono faint nowrap">${r.fired ? 'fired' : r.condition_met ? 'met (outranked)' : '—'}</div>
          </div>`,
        )
        .join(''),
      { subtitle: 'The first satisfied rule sets the terminal state. Later findings are retained, not discarded.' },
    )}`;
}

function contextCard(result) {
  const assessment = result.context_assessment;
  return `
    <h2 class="section">Context assessment</h2>
    ${card(
      `Status: ${assessment.status}`,
      assessment.findings?.length
        ? assessment.findings
            .map(
              (f) => `<div class="finding">
                <span class="sev" data-sev="${esc(f.severity)}">${esc(f.severity)}</span>
                <div class="finding-body">
                  <div class="finding-code">${esc(f.code)}</div>
                  <div class="finding-detail">${esc(f.detail)}</div>
                </div>
              </div>`,
            )
            .join('')
        : '<p class="muted" style="margin:0">No findings. The context satisfied every profile requirement checked, including live control identity and configuration fingerprint.</p>',
      {
        subtitle: assessment.evaluated_against
          ? `observed fingerprint ${assessment.evaluated_against.observed_configuration_fingerprint ?? 'not read'}`
          : '',
      },
    )}`;
}

function candidateCard(result, run) {
  const app = result.candidate_application;
  const cleanup = run?.cleanup_record ?? null;
  const cleanupText = !cleanup
    ? 'performed after the result is durable — see the reference-bundle addendum'
    : cleanup.removed
      ? `removed at ${cleanup.removed_at}`
      : cleanup.not_applicable
        ? 'not applicable — no candidate was applied'
        : (cleanup.detail ?? cleanup.error ?? 'not removed');
  return `
    <h2 class="section">Candidate application state</h2>
    ${card(
      app.state_established ? 'Exact candidate verified active' : `State: ${app.state}`,
      `<dl class="kv">
        <dt>Applied</dt><dd>${esc(String(app.applied))}</dd>
        <dt>State established</dt><dd>${esc(String(app.state_established))}</dd>
        <dt>Applied digest</dt><dd>${esc(app.applied_candidate_digest ?? '—')}</dd>
        <dt>Live digests on control</dt><dd>${esc((app.active_candidate_digests ?? []).join(', ') || '—')}</dd>
        <dt>Rules installed</dt><dd>${esc((app.applied_rule_ids ?? []).join(', ') || '—')}</dd>
        <dt>Removal / reset</dt><dd>${esc(cleanupText)}</dd>
      </dl>
      ${
        cleanup && cleanup.reconciliation_required
          ? `<div class="banner" data-tone="error" style="margin-top:12px"><div><div class="banner-title">Reconciliation required</div><div class="banner-body">${esc(cleanup.detail)} A retry must not reapply the candidate until an operator has reconciled actual control state.</div></div></div>`
          : ''
      }`,
      { subtitle: 'A verdict binds to the digest that was actually live on the control, not merely to the artifact submitted.' },
    )}`;
}

function attackTable(result) {
  if (!result.attack_observations.length) {
    return `<h2 class="section">Attack evidence</h2>${card('No attack cases were executed', empty('No candidate efficacy judgment was formed for this run.'))}`;
  }
  return `
    <h2 class="section">Attack evidence</h2>
    ${card(
      `${result.attack_observations.length} case(s)`,
      `<div class="table-wrap"><table>
        <thead><tr><th>Case</th><th>Proof</th><th>Candidate absent</th><th>Candidate present</th><th>Attribution</th><th>Conclusion</th><th>Evidence</th></tr></thead>
        <tbody>${result.attack_observations
          .map(
            (o) => `<tr>
              <td class="stack"><span class="mono">${esc(o.case_id)}</span>${o.required ? '<span class="chip sm neutral plain">required</span>' : '<span class="faint" style="font-size:11px">not required</span>'}</td>
              <td class="mono faint">${esc(o.proof_strength)}</td>
              <td class="stack"><span class="mono">${esc(o.candidate_absent_observation)}</span><span class="faint" style="font-size:11.5px">${esc(o.candidate_absent_note ?? '')}</span></td>
              <td class="stack"><span class="mono">${esc(o.candidate_present_observation)}</span><span class="faint" style="font-size:11.5px">${esc(o.candidate_present_note ?? '')}</span></td>
              <td class="stack"><span class="mono">${o.attribution.attributed ? 'attributed' : 'not attributed'}</span><span class="faint" style="font-size:11.5px">${esc(o.attribution.reason)}</span></td>
              <td>${conclusionChip(o.conclusion)}</td>
              <td>${evidenceButtons(o.evidence_refs)}</td>
            </tr>`,
          )
          .join('')}</tbody></table></div>
      <div id="evidence-panel"></div>`,
      { subtitle: 'A block counts only when the control names the rule and the exact candidate digest. Generic rejections stay undetermined.' },
    )}`;
}

function benignTable(result) {
  if (!result.benign_observations.length) {
    return `<h2 class="section">Benign (no-harm) evidence</h2>${card('No benign cases were executed', empty('No no-harm judgment was formed for this run.'))}`;
  }
  return `
    <h2 class="section">Benign (no-harm) evidence</h2>
    ${card(
      `${result.benign_observations.length} case(s)`,
      `<div class="table-wrap"><table>
        <thead><tr><th>Case</th><th>Expected</th><th>Observed</th><th>Conclusion</th><th>Evidence</th></tr></thead>
        <tbody>${result.benign_observations
          .map(
            (o) => `<tr>
              <td class="stack"><span class="mono">${esc(o.case_id)}</span>${o.required ? '<span class="chip sm neutral plain">required</span>' : ''}</td>
              <td class="mono faint">${esc(o.expected_outcome)}</td>
              <td class="stack"><span class="mono">${esc(o.candidate_present_observation)}</span><span class="faint" style="font-size:11.5px">${esc(o.candidate_present_note ?? '')}</span></td>
              <td>${conclusionChip(o.conclusion)}</td>
              <td>${evidenceButtons(o.evidence_refs)}</td>
            </tr>`,
          )
          .join('')}</tbody></table></div>`,
      { subtitle: 'No-harm evidence extends only to the supplied representative benign cases.' },
    )}`;
}

function limitations(result) {
  const retained = result.retained_findings;
  return `
    <h2 class="section">Limitations and retained findings</h2>
    ${card(
      'What this result does not establish',
      `<ul class="limitations" style="margin:0;padding-left:18px">
        ${result.limitations.map((l) => `<li><code>${esc(l.code)}</code> — ${esc(l.statement)}</li>`).join('')}
      </ul>
      ${
        retained.attack_failures.length || retained.benign_regressions.length || retained.unresolved_required_evidence.length
          ? `<div style="margin-top:16px"><h3>Retained findings</h3>
            <dl class="kv">
              <dt>Benign regressions</dt><dd>${esc(retained.benign_regressions.join(', ') || 'none')}</dd>
              <dt>Attack failures</dt><dd>${esc(retained.attack_failures.join(', ') || 'none')}</dd>
              <dt>Unresolved evidence</dt><dd>${esc(retained.unresolved_required_evidence.map((u) => `${u.scope}${u.case_id ? `/${u.case_id}` : ''}:${u.code}`).join(', ') || 'none')}</dd>
            </dl></div>`
          : ''
      }`,
      { subtitle: 'Negative and conflicting observations are preserved even when another terminal state governs.' },
    )}`;
}

function evidenceCard(result) {
  return `
    <h2 class="section">Evidence bindings</h2>
    ${card(
      `${result.evidence_bindings.length} claim(s) bound to evidence`,
      `<div class="table-wrap"><table>
        <thead><tr><th>Claim type</th><th>Claim</th><th>Evidence</th></tr></thead>
        <tbody>${result.evidence_bindings
          .map(
            (b) => `<tr>
              <td><span class="chip sm neutral plain">${esc(b.claim_type)}</span></td>
              <td class="muted">${esc(b.claim)}</td>
              <td>${evidenceButtons(b.evidence_refs)}</td>
            </tr>`,
          )
          .join('')}</tbody></table></div>
      <div class="btn-row" style="margin-top:14px">
        <button class="btn sm" data-bundle="${esc(result.result_id)}">Load reference bundle</button>
        <span class="field-hint">Review material sufficient to inspect this result without rerunning validation.</span>
      </div>
      <div id="bundle-panel" style="margin-top:12px"></div>`,
    )}`;
}

function evidenceButtons(refs = []) {
  if (!refs.length) return '<span class="faint">—</span>';
  return refs
    .map((ref) => `<button class="btn sm" data-evidence="${esc(ref)}" style="margin:2px 2px 2px 0">${esc(ref.replace('evidence://', '').slice(0, 8))}…</button>`)
    .join('');
}

/** Wires the evidence and bundle expanders inside a rendered result. */
export function wireEvidence(root) {
  root.querySelectorAll('[data-evidence]').forEach((button) =>
    button.addEventListener('click', async () => {
      const panel = root.querySelector('#evidence-panel') ?? root;
      panel.innerHTML = '<div class="empty"><span class="spinner"></span></div>';
      try {
        const record = await api.evidence(button.dataset.evidence.replace('evidence://', ''));
        panel.innerHTML = `<div style="margin-top:14px">${jsonBlock(`Evidence ${record.kind} · ${record.digest}`, record, { open: true })}</div>`;
      } catch (error) {
        panel.innerHTML = `<div class="banner" data-tone="error"><div class="banner-body">${esc(error.message)}</div></div>`;
      }
    }),
  );

  root.querySelectorAll('[data-bundle]').forEach((button) =>
    button.addEventListener('click', async () => {
      const panel = root.querySelector('#bundle-panel');
      panel.innerHTML = '<div class="empty"><span class="spinner"></span></div>';
      try {
        const bundle = await api.bundle(button.dataset.bundle);
        panel.innerHTML = jsonBlock(`DefenseValidationReferenceBundle@1 · ${bundle.bundle_digest}`, bundle, { open: true });
      } catch (error) {
        panel.innerHTML = `<div class="banner" data-tone="error"><div class="banner-body">${esc(error.message)}</div></div>`;
      }
    }),
  );
}
