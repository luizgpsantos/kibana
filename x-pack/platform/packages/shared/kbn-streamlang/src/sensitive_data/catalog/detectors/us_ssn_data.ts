/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

export const usSsnDetector = {
  id: 'us-ssn',
  displayName: 'US Social Security Number',
  description:
    'US Social Security numbers (9 digits, optionally separated by dashes or spaces). Requires a nearby SSN keyword within 30 characters.',
  categories: ['PII'],
  detection: {
    grokPatterns: ['\\K%{US_SSN:US_SSN}'],
    grokPatternDefinitions: {
      US_SSN: '(?<![0-9])[0-9]{3}[- ]?[0-9]{2}[- ]?[0-9]{4}(?![0-9])',
    },
    validation: {
      type: 'none',
    },
  },
  recommendedAction: 'remove',
  defaultPrecisionGuards: ['Only redact Social Security numbers labeled nearby'],
  anticipatoryAffinity: ['email', 'visa', 'mastercard'],
};
