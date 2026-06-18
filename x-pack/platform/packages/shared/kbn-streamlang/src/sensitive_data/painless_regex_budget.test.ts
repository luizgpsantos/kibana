/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { SensitiveDataCategoryAction } from '../../types/processors';
import { ACTIVE_DETECTOR_IDS } from './catalog';
import { getSupportedActionsForCategory } from './action_capabilities';
import { compileFromCategories } from './compile';

/**
 * Spec 02 Part C — build-time regex budget guard (fast, no Elasticsearch).
 *
 * `partial`/`hash`/`tag`/checksum-`redact` compile to Painless `script` processors that run
 * `/regex/.matcher(...)`. Elasticsearch aborts a matcher op once it visits more than
 * `script.painless.regex.limit-factor (6) × inputLength` characters. A regex run via the UNBOUNDED
 * chunked `matcher.find()` (a 128-char window) can blow that budget on dense input — the runtime-only
 * failure class this sub-roadmap exists to prevent.
 *
 * This guard reads the *actual compiled Painless* and enforces the routing invariant that keeps the
 * budget non-binding by construction:
 *
 *  - No Painless regex at all (native Grok `redact`, or the regex-free `ipv4`/`ipv6` scans) → safe.
 *  - Regex run via the bounded-window matcher (`lookingAt()` on a ≤64-char window) → safe: each
 *    matcher op sees a bounded input, so the limit cannot bind regardless of backtracking.
 *  - Regex run via the unbounded chunked `find()` → only allowed for detectors on
 *    {@link LINEAR_SAFE_CHUNKED}, whose linearity is proven by the Spec 01 real-ES matrix and which
 *    must carry a boundary lookbehind (the cheap structural property that stops `find()` from
 *    restarting at every offset — the dominant >6× cost).
 *
 * If a new detector or a re-routing change makes a non-allowlisted regex run via `find()`, this test
 * fails with guidance. It is a cheap front-line backstop; the Spec 01 matrix remains the
 * authoritative budget check because it runs at the real `limit-factor`.
 */
describe('detector Painless regex budget (Spec 02 Part C guard)', () => {
  const LINEAR_SAFE_CHUNKED = new Set(['email', 'iban', 'mac-address']);

  /** Extracts `REGEX` from a `/REGEX/.matcher(...)` literal (our regexes never contain `/`). */
  const MATCHER_LITERAL = /\/(.+?)\/\.matcher\(/;

  interface RegexMatcher {
    kind: 'chunked' | 'bounded-window';
    regex: string;
  }

  const regexMatchersFor = (id: string, action: SensitiveDataCategoryAction): RegexMatcher[] => {
    const { processors } = compileFromCategories([{ id, action, useRecommendedKeywords: true }], {
      field: 'message',
      withFlags: true,
    });
    const matchers: RegexMatcher[] = [];
    for (const processor of processors) {
      if (!processor || typeof processor !== 'object' || !('script' in processor)) {
        continue;
      }
      const source = (processor as { script?: { source?: string } }).script?.source;
      if (!source || !source.includes('.matcher(')) {
        continue;
      }
      const found = source.match(MATCHER_LITERAL);
      matchers.push({
        kind: source.includes('lookingAt(') ? 'bounded-window' : 'chunked',
        regex: found ? found[1] : '',
      });
    }
    return matchers;
  };

  const detectorsRunViaUnboundedFind = (): Set<string> => {
    const seen = new Set<string>();
    for (const id of ACTIVE_DETECTOR_IDS) {
      for (const action of getSupportedActionsForCategory(id)) {
        for (const matcher of regexMatchersFor(id, action)) {
          if (matcher.kind === 'chunked') {
            seen.add(id);
          }
        }
      }
    }
    return seen;
  };

  for (const id of ACTIVE_DETECTOR_IDS) {
    for (const action of getSupportedActionsForCategory(id)) {
      it(`"${id}" / "${action}" keeps its Painless regex within the chunk-bounded budget`, () => {
        for (const { kind, regex } of regexMatchersFor(id, action)) {
          if (kind === 'bounded-window') {
            // Bounded by the ≤64-char window — the limit-factor budget cannot be exceeded.
            expect(regex.length).toBeGreaterThan(0);
            continue;
          }
          if (!LINEAR_SAFE_CHUNKED.has(id)) {
            throw new Error(
              `Detector "${id}" (action "${action}") runs its regex via the unbounded chunked ` +
                `matcher.find() (regex: ${regex}). This is subject to script.painless.regex.limit-factor ` +
                `over a 128-char chunk and can fail at runtime on dense input. Route it through a ` +
                `regex-free scan or the bounded-window matcher in compile.ts, OR — only after proving ` +
                `it stays under the limit on the Spec 01 real-ES matrix — add it to LINEAR_SAFE_CHUNKED.`
            );
          }
          // Boundary lookbehind: stops find() restarting at every offset (the dominant >6× cost).
          expect(regex).toContain('(?<!');
        }
      });
    }
  }

  it('LINEAR_SAFE_CHUNKED has no stale entries (each is still run via find())', () => {
    const chunked = detectorsRunViaUnboundedFind();
    for (const id of LINEAR_SAFE_CHUNKED) {
      // A stale entry means the detector was migrated to a scan/window — drop it from the allowlist.
      expect([...chunked]).toContain(id);
    }
  });
});
