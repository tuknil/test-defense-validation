# `defense-validation` prototype

A working implementation of the `defense-validation@1.0` capability contract from
[`defense-validation-lld`](./docs/defense-validation-lld.md): a deterministic, asynchronous validation
orchestration service that applies an **exact translated defensive control candidate** in a
dev-equivalent control context, runs an attack suite and a representative benign suite, correlates
mechanical observations, and emits a bounded efficacy/no-harm result with explicit proof strength.

**The service maintains no registry.** A request is self-contained: the caller supplies the exact
candidate artifact, both suites, the validation context descriptor, the profile, and the policy
inline. The console is two screens — **Validate** (one request in, one result out, on the same page)
and **Ledger** (the append-only record of every result). Example payloads live as files in
[`examples/`](./examples) and are editable starting points, not a registry.

SafeBreach and the WAF lab are simulated, behind the same HTTP boundary a real integration would use.

```bash
npm install && npm run dev
```

| Service | Port | Role |
|---|---|---|
| UI | 5173 | Review console (static; holds no credentials or domain logic) |
| API + worker | 8088 | `defense-validation` capability: ingress, orchestration, result engine |
| Simulator | 8099 | External execution plane: dev-equivalent WAF, protected target, SafeBreach vendor API |

```bash
npm test
```

44 tests covering all nine CFS conformance scenarios, the payload contract, the Postgres-backed
ledger, the acceptance criteria, the security boundaries, and determinism.

---

## Three processes, three trust boundaries

The split is not cosmetic. It mirrors the LLD's architecture planes (§3.2) and makes the boundaries
testable rather than asserted.

```
  ui/  :5173  ──HTTP──▶  api/  :8088  ──HTTP──▶  sim/  :8099
  static host             capability                external execution plane
  no secrets              private ingress           WAF + target + BAS vendor
                          worker + result engine
```

* **`ui/`** is a static file server. The browser talks to the API directly. The UI cannot reach the
  control plane at all.
* **`api/`** owns the capability contract. The API process authenticates, validates the payload,
  derives input identities, applies the security boundary, and enqueues; the worker owns every
  domain decision. Neither has a path to a production control, and neither stores or resolves
  submitted material by ID.
* **`sim/`** is the vendor side. It holds the real rule state and decides block/allow. The API only
  ever *observes* it over HTTP, so the result engine is reading genuine external evidence rather
  than a fixture that already knows the answer.

Point `CONTROL_PLANE_BASE_URL` and `SAFEBREACH_BASE_URL` at real systems and nothing in the
capability changes — that is what the adapter split (ADR-003) buys.

## What the simulator actually simulates

`sim/` hosts six control instances (`sim/src/instances.js`), each a WAF engine in front of a
protected non-prod app:

* **`POST /waf/v1/instances/:id/policies/:ref/rules`** — apply an exact native candidate artifact.
* **`POST /waf/v1/instances/:id/traffic`** — send one request through the control to the target.
  Returns the control decision (with or without rule attribution) and the target receipt (with
  behavior markers such as `vulnerable-behavior` or `discriminator-target`).
* **`POST /safebreach/v1/executions`** + **`GET /safebreach/v1/executions/:id`** — vendor-shaped
  scenario execution with polling, deliberately speaking "scenarios / simulators / verdicts" so the
  runner adapter has to do real normalization.

The engine applies URL-decoding before matching (as a real rule chain's `t:urlDecodeUni` would),
evaluates pre-installed rules *before* the candidate, and emits a credential in every response so
that redaction has something real to strip.

The instances differ in ways that produce genuinely different evidence: one runs an unsupported
engine version, one has drifted from its approved configuration fingerprint, one emits generic
rejections with no attribution, one sits behind a legacy edge filter that shadows the candidate, and
one fails rule commits without acknowledgement.

## The request payload

`POST /v1/defense-validation-runs` takes one self-contained object:

```
contract_id           "defense-validation@1.0"
control_candidate     id, target class/technology, translation ancestry, and the exact
                      native artifact (rules) — optionally a digest, which is checked
attack_suite          id, modality, and cases (proof strength, expected candidate-absent
                      behavior, request)
benign_suite          id, modality, and cases (expected permitted outcome, request)
validation_context    control identity + configuration fingerprint, adapter + instance +
                      policy ref, runner adapter, isolation, observation, fidelity claims
validation_profile    supported versions/modalities/proof paths, required observation,
                      required fidelity, baseline and attribution requirements
validation_policy     which cases are required, baseline/attribution flags, limits, retention
```

The full JSON Schema is served at `GET /v1/contract`. `POST /v1/defense-validation-runs/validate`
checks a payload and returns the identities it would derive, without creating a run — that is what
the console's **Check contract** button calls.

Three things follow from having no registry, and each is enforced rather than assumed:

* **Digests are derived, never trusted.** The candidate digest is computed from the supplied
  artifact. A `digest` in the payload is treated as an assertion to check, and a mismatch is refused
  — so a verdict can never bind to material other than what ran.
* **Unknown fields are refused, at any depth.** A payload cannot introduce semantics the contract
  does not define, so it cannot alter policy, scope, or expected outcomes (§13.4).
* **Identifiers that reach a URL are character-constrained.** `instance_id`, `target_policy_ref`,
  and the adapter/simulator IDs must match `^[A-Za-z0-9][A-Za-z0-9._:@-]*$`, and adapters encode
  every path segment regardless. Without both, a traversal in `instance_id` normalizes away the API
  prefix and steers the control adapter to an arbitrary endpoint on the control-plane host.
* **Adapters and limits come from deployment config, not the payload.** The context may only name an
  admitted control/runner adapter, and service caps on rules, cases, and pattern length hold no
  matter what the supplied policy claims.

## Example payloads

`examples/` holds one file per scenario plus an `index.json` describing them. Each file is a bare,
complete payload, so it can be submitted directly with no unwrapping:

```bash
curl -X POST 'localhost:8088/v1/defense-validation-runs?force=true' \
  -H 'Authorization: Bearer dev-submitter-token' \
  -H 'Content-Type: application/json' \
  -d @examples/conf-01-validated.json
```

The console reads the same directory to populate its **Start from** picker. Nothing in `examples/`
is consulted during a run — a validation binds only to the payload that was submitted. Add or edit
files freely; the API rereads the directory on `GET /v1/example-payloads?reload=true`.

Each example is asserted in `api/tests/conformance.test.js`. None declares its own answer; the
terminal state has to be earned from observations.

| | Scenario | Terminal state |
|---|---|---|
| CONF-01 | Direct proof; attacks blocked, benign preserved | `validated` / `direct` |
| CONF-02 | Discriminator-backed cases | `validated` / `indirect` + limitation |
| CONF-03 | A required attack still reaches the target | `failed-to-block` |
| CONF-04 | Over-broad candidate regresses benign traffic | `unsafe` (attack failure retained) |
| CONF-05 | Engine version outside the profile | `environment-invalid` |
| CONF-05b | Live configuration fingerprint drift | `environment-invalid` |
| CONF-06 | Generic rejection, no attribution | `inconclusive` |
| CONF-07 | Stateful browser suite under a stateless profile | `scope-declined` |
| CONF-07b | Indirect suite under a direct-only profile | `scope-declined` |
| CONF-08 | Rule commit times out, state unknown | `malfunction` |
| CONF-09 | Same block with and without the candidate | `inconclusive` |
| SEC-01 | Production context named in a submission | rejected `403` at the edge |

## The result ledger: embedded PostgreSQL

Results, evidence, and reference bundles live in a real PostgreSQL (18.3) running in-process via
[PGlite](https://pglite.dev) — no server to install, no container, `npm run dev` and it is there.
Data lands in `data/pgdata`; point `DATA_DIR` elsewhere to relocate it.

```sql
defense_validation_result (result_id PK, run_id, recorded_at, terminal_state, proof_strength,
                           control_candidate_id, candidate_digest, validation_context_id,
                           replay_key, result JSONB)
evidence_object           (digest PK, kind, run_id, stored_at, claim_types TEXT[], payload JSONB)
reference_bundle          (bundle_digest PK, result_id, built_at,
                           supersedes_bundle_digest, bundle JSONB)
```

**Why JSON columns.** The result is stored exactly as the engine emitted it, in `jsonb` — no lossy
flattening into a table shape that would then need reassembling to review. The handful of dimensions
the ledger filters and sorts on are lifted into typed columns beside the document and indexed, and a
GIN index covers the rest. Aggregates run in SQL over the document rather than in the application:

```sql
SELECT count(*) FROM jsonb_array_elements(result -> 'attack_observations') o
WHERE (o ->> 'required')::boolean AND o ->> 'conclusion' = 'blocked-as-required'
```

**Immutability is enforced by the database, not by convention.** `defense_validation_result` and
`reference_bundle` carry `DO INSTEAD NOTHING` rules on UPDATE and DELETE, so a stored result cannot
be rewritten or removed even by a bug; the primary key makes first-write-wins. A test issues a real
`UPDATE ... SET terminal_state = 'validated'` and asserts the row is unchanged. (Those rules are also
why inserts cannot use `ON CONFLICT` — PostgreSQL forbids the combination — so duplicates are
absorbed by catching `23505`.)

The cleanup addendum is a *new* bundle row naming the digest it supersedes, so the original bundle
stays retrievable and the revision chain is auditable.

`GET /v1/ledger` serves the record with a terminal-state distribution and per-entry required-case
counts; the **Ledger** screen renders it and expands any entry into the full result.

Swapping this for a managed PostgreSQL means changing the connection in `api/src/adapters/db.js` —
the schema and every query stay as they are.

## Where the CFS invariants live

| Invariant | Implementation |
|---|---|
| Exact candidate binding | `input_binding.js` derives the digest from the supplied artifact; `modsecurity.js#verifyApplied` proves that digest is live before any candidate-present trial |
| Context validity first | `context_evaluator.js` — descriptor *and* live probe vs. the signed profile, before any candidate judgment |
| Attribution required | `case_evaluation.js#attributeBlock` — a block counts only when the control names both the rule and the candidate digest |
| Proof strength explicit | `case_evaluation.js#aggregateProofStrength` — `direct` / `indirect` / `mixed` / `not-established` |
| Terminal precedence | `aggregate_result.js` — an ordered rule list; every rule's outcome is recorded, not just the one that fired |
| Uncertainty preserved | unresolved evidence is retained as limitations even when a negative state governs |
| No overclaim | `invariants.js` — a failed invariant check downgrades the result to `malfunction` rather than shipping an unsound verdict |
| No secrets | `invariants.js#redact` on every evidence write, asserted against a simulator that really does emit one |

### One reading decision worth flagging

§7.6 lists `inconclusive` above `unsafe`, qualified by "unresolved required evidence *that could
change candidate judgment*". Taken literally, an unresolved attack case would mask an established
benign regression — which contradicts §2.4 and §8.1, where `unsafe` governs and both findings are
retained.

`aggregate_result.js` resolves this by honouring the qualifier: an established required-benign
regression is a governing negative that no unresolved evidence can overturn, so it is not masked;
the unresolved items are retained as limitations instead. The same reasoning lets an established
attack failure stand as `failed-to-block`, but *only* once benign evidence, context, and candidate
state are fully resolved — an unresolved benign case could still hide a regression that outranks it.

The full ordered evaluation is rendered on every run detail page, so the decision is inspectable
rather than implicit. The rationale is documented at the top of the module.

## Lifecycle detail: cleanup is post-result

A run reports `terminal_state` as soon as the verdict is decided and the result is
durable — but candidate removal happens *after* that (§5.2 step 16). Poll `finalized`
instead if you need the cleanup outcome, including the reconciliation-required signal
after an indeterminate apply.


Per §5.2, candidate removal happens *after* the authoritative result is durable. Removal evidence
therefore cannot live inside the immutable result. It is recorded on the run and attached to the
reference bundle as an explicitly timestamped `post_result_addendum`, and the bundle digest is
re-derived. After an indeterminate apply, removal is **withheld** rather than attempted, because
§12.2 forbids acting on unknown control state — the run reports `reconciliation-required`.

## API

```
POST /v1/defense-validation-runs              submit (202; ?force=true bypasses replay dedupe)
POST /v1/defense-validation-runs/validate     contract check only, creates nothing
GET  /v1/defense-validation-runs              list, filterable by terminal_state
GET  /v1/defense-validation-runs/{run_id}     lifecycle state, live pipeline steps, submitted payload
                                              (`terminal_state` = verdict durable;
                                               `finalized` = run wound down, cleanup evidenced)
GET  /v1/defense-validation-results/{id}      immutable result
GET  /v1/defense-validation-results/{id}/reference-bundle
GET  /v1/evidence/{digest}                    content-addressed evidence object
GET  /v1/example-payloads                     files from examples/ (?reload=true rereads disk)
GET  /v1/ledger                               append-only result record, filterable
GET  /v1/events                               completion-event outbox
GET  /v1/audit                                append-only audit trail
GET  /v1/metrics                              terminal-state distribution, queue, DLQ
GET  /v1/contract                             schema, limits, adapter allowlists, terminal states
```

Auth is a stand-in for workload identity: `Authorization: Bearer <token>` with
`dev-submitter-token`, `dev-operator-token`, or `dev-viewer-token`. The UI's identity switcher
changes the token so the RBAC is observable — submitting as the viewer returns `403`.

## Layout

```
lib/            shared HTTP + digest helpers
sim/            external execution plane (WAF engine, protected target, SafeBreach vendor API)
api/
  src/domain/   contract validation, input binding, admission, context evaluator,
                case evaluation, precedence, invariants
  src/adapters/ control, runner (local-http + safebreach), observation normalizer,
                evidence, db (embedded postgres), examples loader, persistence
  src/worker/   queue + the 17-step orchestration
  tests/        conformance, acceptance, security, determinism
examples/       one payload file per scenario + index.json
data/pgdata/    embedded PostgreSQL cluster (gitignored)
ui/             static console: Validate + Ledger
```

## Prototype limitations

These are deliberate for a prototype and are the gap between this and §21's exit criteria:

* **Only the durable half is in PostgreSQL.** Results, evidence, and bundles survive restarts. Run
  lifecycle rows, the audit trail, and the outbox are still in-memory and clear on restart — a run
  is mutable until terminal and its steps churn on every transition, so that split is deliberate,
  but §11.1 wants those tables too.
* **PGlite is single-connection.** Queries serialize, and there is no connection pool, no replica,
  and no concurrent writer. Fine for a prototype; a managed PostgreSQL is the drop-in.
* **The ledger has no retention enforcement.** `retention_days` is recorded on every result and
  never acted on, and the ledger file grows without bound or rotation (§11.3, GAP-05).
* **The queue is in-process.** It preserves bounded concurrency, per-context serialization, bounded
  retries, and a DLQ, but not cross-process durability.
* **Signatures are asserted, not verified.** Profiles and policies carry signature fields and are
  refused if absent, but since they now arrive in the payload, a caller effectively self-attests.
  Real provenance verification (§13.3) is the missing control, and it matters more under this
  contract than it did with a registry.
* **Rule patterns are capped, not analysed.** Patterns must compile and are length-limited, but a
  catastrophically backtracking regex is not detected. A real deployment needs a matching timeout in
  the control adapter.
* **No Terraform.** §4.6's module layout is not built.
* **One control technology.** ModSecurity-class only, which is GAP-01 in the LLD.
