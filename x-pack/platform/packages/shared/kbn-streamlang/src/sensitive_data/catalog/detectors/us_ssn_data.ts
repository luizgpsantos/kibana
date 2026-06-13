/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Vendored from elastic-redact-pii/catalog/detectors/us-ssn.json @ 972ad43 — local knowledge base,
 * not a Kibana build/test dependency. Keep in sync manually.
 *
 * No checksum applies to an SSN, so a nearby keyword (ssn, ss#, soc sec, social security [number],
 * tax id) plus structural rules carry the false-positive defense. The grok pattern uses `\K` to keep
 * the keyword prefix and redact only the number, so it stays in the combined structural redact.
 */
export const usSsnDetector = {
  id: 'us-ssn',
  displayName: 'US Social Security Number',
  description:
    'US SSN (9 digits, optionally separated by dashes or spaces). Requires a nearby SSN keyword plus structural rules (valid area/group/serial) to avoid redacting unrelated 9-digit numbers.',
  categories: ['PII'],
  detection: {
    grokPatterns: [
      '(?i)(?:ssns?|ss#|soc(?: |_)?sec(?:urity)?|social(?: |_)?security(?:(?: |_)?(?:number|no\\.?|#))?|tax(?: |_)?id(?:entification)?(?:(?: |_)?number)?)[^0-9]{0,20}\\K%{US_SSN:US_SSN}',
    ],
    grokPatternDefinitions: {
      US_SSN:
        '(?<![0-9])(?!000|666|9[0-9]{2})[0-9]{3}[- ]?(?!00)[0-9]{2}[- ]?(?!0000)[0-9]{4}(?![0-9])',
    },
    validation: {
      type: 'none',
    },
  },
  recommendedAction: 'remove',
  defaultPrecisionGuards: ['Only redact Social Security numbers labeled nearby'],
  anticipatoryAffinity: ['date-of-birth', 'credit-card', 'email'],
};
