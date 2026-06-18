/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { expect } from '@kbn/scout/api';
import { tags } from '@kbn/scout';
import {
  ACTIVE_DETECTOR_IDS,
  getCategoryMaskToken,
  getSupportedActionsForCategory,
  requiresKeywordProximity,
  withRecommendedKeywords,
  type SensitiveDataCategory,
  type SensitiveDataCategoryAction,
} from '@kbn/streamlang';
import { streamsApiTest as apiTest } from '../../fixtures';
import { COMMON_API_HEADERS } from '../../fixtures/constants';

/**
 * Data-driven safety net for the `sensitive_data` Painless scripts.
 *
 * Unit tests and golden fixtures only assert the *string* of the compiled processor — a
 * `script.painless.regex.limit-factor` violation is a runtime error in Elasticsearch and is
 * therefore invisible to them. `hash`, `partial`, `tag`, and checksum-confirmed `redact` all run
 * `/regex/.matcher(...)` in Painless; a backtracking-heavy regex can exceed the limit on a single
 * 128-char chunk even after chunking.
 *
 * This spec compiles and *executes* the pipeline against real Elasticsearch via the Streams
 * `_simulate` endpoint for every active detector × every supported action × an adversarial,
 * multi-KB input, and asserts the pipeline runs without a Painless error. The matrix is derived
 * from `ACTIVE_DETECTOR_IDS`, so new detectors are covered automatically and a missing sample
 * value fails the suite.
 *
 * `logs.otel` is an OTel stream, so the telemetry flags land under `attributes.sensitive_data.*`.
 *
 * See roadmap: src/sensitive_data/roadmap/painless_regex_safety/01_executable_painless_matrix_tests.md
 */

interface SimulationError {
  message: string;
  type?: string;
  processor_id?: string;
}

interface SimulationDocument {
  value: Record<string, unknown>;
  errors: SimulationError[];
  status: string;
}

interface SimulationResponse {
  documents: SimulationDocument[];
  definition_error?: SimulationError;
}

/**
 * Worst-case backtracking shape per detector family. The unit is repeated to fill the adversarial
 * input; dense separators + the characters each pattern allows is what actually trips the
 * limit-factor.
 */
type AdversarialFamily = 'digits' | 'email' | 'ipv4' | 'ipv6' | 'mac';

interface DetectorSample {
  /** A real, matchable instance of this detector's PII. */
  value: string;
  /** Proximity keyword for keyword-gated detectors (placed immediately before the value). */
  keyword?: string;
  family: AdversarialFamily;
}

/**
 * One realistic, matchable sample per active detector. Keywords are members of each detector's
 * recommended-keyword set so `withRecommendedKeywords` + this keyword make the detector fire.
 *
 * IMPORTANT: every id in `ACTIVE_DETECTOR_IDS` must have an entry here — the coverage test below
 * fails otherwise, forcing a sample when a detector is added.
 */
const SAMPLE_VALUE_BY_DETECTOR: Record<string, DetectorSample> = {
  email: { value: 'alice.smith@example.com', family: 'email' },
  visa: { value: '4111 1111 1111 1111', keyword: 'card', family: 'digits' },
  mastercard: { value: '5555 5555 5555 4444', keyword: 'card', family: 'digits' },
  amex: { value: '3782 822463 10005', keyword: 'card', family: 'digits' },
  discover: { value: '6011 1111 1111 1117', keyword: 'card', family: 'digits' },
  diners: { value: '3056 9309 0259 04', keyword: 'card', family: 'digits' },
  jcb: { value: '3530 1113 3330 0000', keyword: 'card', family: 'digits' },
  maestro: { value: '6759 6498 2643 8453', keyword: 'card', family: 'digits' },
  iban: { value: 'DE89 3704 0044 0532 0130 00', keyword: 'iban', family: 'digits' },
  'us-ssn': { value: '123-45-6789', keyword: 'ssn', family: 'digits' },
  ipv4: { value: '192.168.1.100', family: 'ipv4' },
  ipv6: { value: '2001:0db8:85a3:0000:0000:8a2e:0370:7334', family: 'ipv6' },
  'mac-address': { value: '00:1A:2B:3C:4D:5E', family: 'mac' },
};

/** Dense, separator-heavy filler that does not contain a proximity keyword (so it cannot match
 *  keyword-gated detectors) but maximizes regex work for the matched family. */
const ADVERSARIAL_UNIT: Record<AdversarialFamily, string> = {
  digits: '0123 4567-8901.2345 6789-0123.4567 8901-2345.6789 ',
  email: 'aaaa.bbbb+cccc.dddd_eeee-ffff.gggg_hhhh-iiii.jjjj@sub.domain.example ',
  ipv4: '111.222.333.444 10.0.0.1 255.255.255.255 172.16.254.1 ',
  ipv6: 'abcd:1234:5678:9abc:def0:1234:5678:9abc fedc:ba98:7654:3210:0011:2233:4455:6677 ',
  mac: 'aa:bb:cc:dd:ee:ff 00:11:22:33:44:55 a1:b2:c3:d4:e5:f6 ',
};

/** ~4 KB adversarial run on each side of the value spans many 128-char chunks (chunk = 128,
 *  overlap = 64) and exercises cross-chunk handling. */
const ADVERSARIAL_TARGET_BYTES = 4096;

const repeatToBytes = (unit: string, targetBytes: number): string =>
  unit.repeat(Math.ceil(targetBytes / unit.length)).slice(0, targetBytes);

/** keyword + value, with a single space so the keyword stays within proximity of the value. */
const matchCore = (sample: DetectorSample): string =>
  sample.keyword ? `${sample.keyword} ${sample.value}` : sample.value;

/** Realistic positive: value pushed past many chunks by benign filler. */
const buildPositiveInput = (sample: DetectorSample): string => {
  const lead = repeatToBytes('lorem ipsum dolor sit amet consectetur ', 512);
  const tail = repeatToBytes('the quick brown fox jumps over the lazy dog ', 512);
  return `${lead} ${matchCore(sample)} ${tail}`;
};

/** Adversarial: the match surrounded by a pathological, separator-dense run for its family. */
const buildAdversarialInput = (sample: DetectorSample): string => {
  const filler = repeatToBytes(ADVERSARIAL_UNIT[sample.family], ADVERSARIAL_TARGET_BYTES);
  return `${filler} ${matchCore(sample)} ${filler}`;
};

const buildCategory = (id: string, action: SensitiveDataCategoryAction): SensitiveDataCategory => {
  const base: SensitiveDataCategory =
    action === 'partial' ? { id, action, keepLast: 4 } : { id, action };
  return requiresKeywordProximity(id) ? withRecommendedKeywords(base) : base;
};

apiTest.describe(
  'Stream data processing - sensitive_data Painless regex-limit matrix',
  { tag: [...tags.stateful.classic, ...tags.serverless.observability.complete] },
  () => {
    const testStream = 'logs.otel';
    const sourceField = 'body.text';

    // Build-time coverage guard: fail the whole spec (listing all gaps at once) if a new active
    // detector lacks a sample. Kept out of `apiTest` since it makes no API/ES call.
    const missingSamples = ACTIVE_DETECTOR_IDS.filter((id) => !(id in SAMPLE_VALUE_BY_DETECTOR));
    if (missingSamples.length > 0) {
      throw new Error(
        `Add a SAMPLE_VALUE_BY_DETECTOR entry for new detector(s): ${missingSamples.join(', ')}`
      );
    }

    for (const id of ACTIVE_DETECTOR_IDS) {
      for (const action of getSupportedActionsForCategory(id)) {
        apiTest(
          `${id} / ${action}: compiles and runs without a Painless error on adversarial input`,
          async ({ apiClient, samlAuth }) => {
            const sample = SAMPLE_VALUE_BY_DETECTOR[id];
            if (!sample) {
              throw new Error(`Missing SAMPLE_VALUE_BY_DETECTOR entry for detector "${id}"`);
            }

            const { cookieHeader } = await samlAuth.asStreamsAdmin();
            const category = buildCategory(id, action);

            const { statusCode, body } = await apiClient.post(
              `internal/streams/${testStream}/processing/_simulate`,
              {
                headers: { ...COMMON_API_HEADERS, ...cookieHeader },
                body: {
                  processing: {
                    steps: [
                      { action: 'sensitive_data', from: sourceField, categories: [category] },
                    ],
                  },
                  documents: [
                    {
                      [sourceField]: buildPositiveInput(sample),
                      '@timestamp': new Date().toISOString(),
                    },
                    {
                      [sourceField]: buildAdversarialInput(sample),
                      '@timestamp': new Date().toISOString(),
                    },
                  ],
                },
                responseType: 'json',
              }
            );

            const response = body as SimulationResponse;

            // 1. Core guarantee: no Painless compile / regex-limit failure anywhere.
            expect(statusCode).toBe(200);
            expect(
              response.definition_error,
              `${id}/${action}: simulate returned a definition error: ${response.definition_error?.message}`
            ).toBeUndefined();
            expect(response.documents).toHaveLength(2);

            for (const [index, doc] of response.documents.entries()) {
              expect(
                doc.errors,
                `${id}/${action}: document #${index} reported processing errors: ${doc.errors
                  .map((e) => e.message)
                  .join(' | ')}`
              ).toStrictEqual([]);
            }

            // 2. Action semantics on the realistic positive document (detection fired).
            const positive = response.documents[0];
            const text = positive.value[sourceField] as string;
            const detected = positive.value['attributes.sensitive_data.detected'];
            const categories = positive.value['attributes.sensitive_data.categories'];

            expect(detected, `${id}/${action}: expected detection to fire`).toBe(true);
            expect(categories).toContain(id);

            // Boolean-folded so the assertions stay unconditional (playwright/no-conditional-expect):
            // `tag` preserves the value, every other action removes it.
            expect(text.includes(sample.value), `${id}/${action}: value presence`).toBe(
              action === 'tag'
            );

            // `redact` emits the category mask token when one is defined.
            const maskToken = action === 'redact' ? getCategoryMaskToken(id) : undefined;
            expect(maskToken ? text.includes(maskToken) : true, `${id}/redact: mask token`).toBe(
              true
            );

            // `hash` emits an h:<16 hex> fingerprint.
            expect(
              action !== 'hash' || /h:[0-9a-f]{16}/.test(text),
              `${id}/hash: expected an h:<16 hex> fingerprint`
            ).toBe(true);
          }
        );
      }
    }
  }
);
