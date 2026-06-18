# `sensitive_data` Painless performance benchmark

Committed, repeatable benchmark for the per-document cost of the `sensitive_data` Painless scans
(roadmap Spec 03). It exists so we notice CPU regressions before they reach a customer's ingest node.

## Files

- `painless_perf.ts` — pure harness: the realistic + adversarial corpus, the detector × action grid
  (compiled with telemetry on), percentile/summary math, and the relative-budget evaluator. The pure
  parts are covered by `painless_perf.test.ts` in the normal unit lane, so the harness can't bit-rot.
- `perf_budget.json` — committed baseline. Budgets are **relative** (per-document cost ÷ a no-op
  pipeline measured in the same run) so they travel across CI agents of differing speed. The gate
  targets gross 2–10× regressions, not 5% jitter.
- `integration_tests/painless_perf.test.ts` — the opt-in ES gate (jest_integration, node env).

## Running the gate

The gate needs a running Elasticsearch and is **skipped unless `RUN_PAINLESS_PERF=1`** so it never
slows the default unit run.

```bash
RUN_PAINLESS_PERF=1 TEST_ES_URL=http://localhost:9200 TEST_ES_AUTH=elastic:changeme \
  node scripts/jest_integration \
    --config x-pack/platform/packages/shared/kbn-streamlang/jest.integration.config.js \
    x-pack/platform/packages/shared/kbn-streamlang/src/sensitive_data/__bench__/integration_tests/painless_perf.test.ts
```

Knobs: `PAINLESS_PERF_DOCS` (docs per `_simulate` request, default 200), `PAINLESS_PERF_ROUNDS`
(measured rounds after warm-up, default 5; use ≥20 for a low-noise baseline). Auth can also be a full
header via `TEST_ES_AUTH_HEADER`. Raw results are written to
`target/painless_perf/last_run.json` (git-ignored) for run-to-run comparison.

The committed baseline was captured on a snapshot ES at `script.painless.regex.limit-factor=6`
(25 rounds × 200 docs) with ~2× headroom. Re-baseline on a dedicated perf agent; bump a budget value
only as a deliberate, reviewed change that documents the regression decision.

## Cost model (why budgets differ by action)

- **redact** (the default) is the cheapest: it runs as the native Grok `redact` processor for most
  detectors, so its relative cost stays ~1–2× the no-op baseline.
- **hash / partial / tag** and **checksum redact** run a **per-candidate Painless scan** over the
  field. Cost scales with field size and the number of candidate matches, so on the adversarial
  corpus these land ~5–18× the no-op baseline.
- **`MAX_SCAN_CHARS` (32 KB)** in `compile.ts` caps how far any per-candidate scan looks for new match
  starts. A single multi-megabyte field can't dominate an ingest node; characters past the cap pass
  through unchanged and the document is flagged `<namespace>.truncated` when telemetry is on.

Guidance for users: scope the processor to the specific field(s) that carry PII rather than a large
free-text body, and prefer full `redact` unless you specifically need a reversible hash, a masked
tail, or detection-only tagging.
