/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { ElasticsearchClient } from '@kbn/core/server';
import type { StreamlangDSL } from '@kbn/streamlang';
import {
  PAINLESS_REGEX_DISABLED_MESSAGE,
  checkSensitiveDataPainlessRegex,
  isPainlessRegexDisabled,
  processingUsesChecksumRedaction,
} from './painless_regex_guard';

const mockEsClient = (settings: {
  transient?: Record<string, unknown>;
  persistent?: Record<string, unknown>;
  defaults?: Record<string, unknown>;
}): ElasticsearchClient =>
  ({
    cluster: {
      getSettings: jest.fn().mockResolvedValue({
        transient: settings.transient ?? {},
        persistent: settings.persistent ?? {},
        defaults: settings.defaults ?? {},
      }),
    },
  } as unknown as ElasticsearchClient);

describe('painless_regex_guard', () => {
  describe('processingUsesChecksumRedaction', () => {
    it('is true for a checksum detector (credit-card)', () => {
      const processing: StreamlangDSL = {
        steps: [
          {
            action: 'sensitive_data',
            from: 'message',
            categories: [{ id: 'credit-card', action: 'redact' }],
          },
        ],
      };
      expect(processingUsesChecksumRedaction(processing)).toBe(true);
    });

    it('is false for structural-only detectors (email/date-of-birth)', () => {
      const processing: StreamlangDSL = {
        steps: [
          {
            action: 'sensitive_data',
            from: 'message',
            categories: [
              { id: 'email', action: 'redact' },
              { id: 'date-of-birth', action: 'redact' },
            ],
          },
        ],
      };
      expect(processingUsesChecksumRedaction(processing)).toBe(false);
    });

    it('is false when a checksum detector runs in structural_only mode (no regex script)', () => {
      const processing: StreamlangDSL = {
        steps: [
          {
            action: 'sensitive_data',
            from: 'message',
            categories: [{ id: 'credit-card', action: 'redact' }],
            structural_only: true,
          },
        ],
      };
      expect(processingUsesChecksumRedaction(processing)).toBe(false);
    });

    it('finds checksum steps nested inside condition blocks', () => {
      const processing: StreamlangDSL = {
        steps: [
          {
            condition: {
              field: 'level',
              eq: 'error',
              steps: [
                {
                  action: 'sensitive_data',
                  from: 'message',
                  categories: [{ id: 'iban', action: 'redact' }],
                },
              ],
            },
          },
        ],
      };
      expect(processingUsesChecksumRedaction(processing)).toBe(true);
    });
  });

  describe('isPainlessRegexDisabled', () => {
    it('is true only when the setting is explicitly "false"', async () => {
      expect(
        await isPainlessRegexDisabled(
          mockEsClient({ persistent: { 'script.painless.regex.enabled': 'false' } })
        )
      ).toBe(true);
    });

    it('is false for the default "limited"', async () => {
      expect(
        await isPainlessRegexDisabled(
          mockEsClient({ defaults: { 'script.painless.regex.enabled': 'limited' } })
        )
      ).toBe(false);
    });

    it('is false when unset', async () => {
      expect(await isPainlessRegexDisabled(mockEsClient({}))).toBe(false);
    });
  });

  describe('checkSensitiveDataPainlessRegex', () => {
    it('returns the guard message when checksum redaction meets a disabled cluster', async () => {
      const processing: StreamlangDSL = {
        steps: [
          {
            action: 'sensitive_data',
            from: 'message',
            categories: [{ id: 'credit-card', action: 'redact' }],
          },
        ],
      };
      const esClient = mockEsClient({ persistent: { 'script.painless.regex.enabled': 'false' } });
      expect(await checkSensitiveDataPainlessRegex(processing, esClient)).toBe(
        PAINLESS_REGEX_DISABLED_MESSAGE
      );
    });

    it('returns undefined for structural-only processing even when regex is disabled', async () => {
      const processing: StreamlangDSL = {
        steps: [
          {
            action: 'sensitive_data',
            from: 'message',
            categories: [{ id: 'email', action: 'redact' }],
          },
        ],
      };
      const esClient = mockEsClient({ persistent: { 'script.painless.regex.enabled': 'false' } });
      expect(await checkSensitiveDataPainlessRegex(processing, esClient)).toBeUndefined();
      expect(esClient.cluster.getSettings).not.toHaveBeenCalled();
    });
  });

  it('accepts legacy string[] categories via normalization', () => {
    // Backward-compat: persisted pipelines may still store category ids as strings.
    const processing = {
      steps: [{ action: 'sensitive_data', from: 'message', categories: ['credit-card'] }],
    } as unknown as StreamlangDSL;
    expect(processingUsesChecksumRedaction(processing)).toBe(true);
  });

  describe('categoryUsesPainlessRegex', () => {
    it('does not throw for an unknown category id and returns false', () => {
      const processing: StreamlangDSL = {
        steps: [
          {
            action: 'sensitive_data',
            from: 'message',
            categories: [{ id: 'not-a-detector', action: 'redact' }],
          },
        ],
      };
      expect(() => processingUsesChecksumRedaction(processing)).not.toThrow();
      expect(processingUsesChecksumRedaction(processing)).toBe(false);
    });

    // --- Bug regression: partial and tag actions emit Painless regex scripts regardless of
    //     whether the detector uses a checksum. The guard must fire for those too. ---

    it('is true for a non-checksum detector with partial action', () => {
      const processing: StreamlangDSL = {
        steps: [
          {
            action: 'sensitive_data',
            from: 'message',
            categories: [{ id: 'email', action: 'partial' }],
          },
        ],
      };
      expect(processingUsesChecksumRedaction(processing)).toBe(true);
    });

    it('is true for a non-checksum detector with tag action', () => {
      const processing: StreamlangDSL = {
        steps: [
          {
            action: 'sensitive_data',
            from: 'message',
            categories: [{ id: 'date-of-birth', action: 'tag' }],
          },
        ],
      };
      expect(processingUsesChecksumRedaction(processing)).toBe(true);
    });

    it('is true for us-ssn with partial action (keyword-gated structural detector)', () => {
      const processing: StreamlangDSL = {
        steps: [
          {
            action: 'sensitive_data',
            from: 'message',
            categories: [{ id: 'us-ssn', action: 'partial' }],
          },
        ],
      };
      expect(processingUsesChecksumRedaction(processing)).toBe(true);
    });
  });

  describe('PAINLESS_REGEX_DISABLED_MESSAGE accuracy', () => {
    it('mentions partial and tag actions alongside checksum detectors', () => {
      expect(PAINLESS_REGEX_DISABLED_MESSAGE).toMatch(/partial/i);
      expect(PAINLESS_REGEX_DISABLED_MESSAGE).toMatch(/tag/i);
      expect(PAINLESS_REGEX_DISABLED_MESSAGE).toMatch(/credit card/i);
      expect(PAINLESS_REGEX_DISABLED_MESSAGE).toMatch(/iban/i);
    });

    it('returns the guard message for email+partial on a regex-disabled cluster', async () => {
      const processing: StreamlangDSL = {
        steps: [
          {
            action: 'sensitive_data',
            from: 'message',
            categories: [{ id: 'email', action: 'partial' }],
          },
        ],
      };
      const esClient = mockEsClient({ persistent: { 'script.painless.regex.enabled': 'false' } });
      const result = await checkSensitiveDataPainlessRegex(processing, esClient);
      expect(result).toBe(PAINLESS_REGEX_DISABLED_MESSAGE);
      // The message must not mislead the user by naming only checksum detectors
      expect(result).toMatch(/partial/i);
    });

    it('returns the guard message for date-of-birth+tag on a regex-disabled cluster', async () => {
      const processing: StreamlangDSL = {
        steps: [
          {
            action: 'sensitive_data',
            from: 'message',
            categories: [{ id: 'date-of-birth', action: 'tag' }],
          },
        ],
      };
      const esClient = mockEsClient({ persistent: { 'script.painless.regex.enabled': 'false' } });
      const result = await checkSensitiveDataPainlessRegex(processing, esClient);
      expect(result).toBe(PAINLESS_REGEX_DISABLED_MESSAGE);
    });
  });
});
