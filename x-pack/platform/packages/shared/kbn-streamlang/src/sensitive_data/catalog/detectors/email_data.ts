/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/** Vendored from elastic-redact-pii/catalog/detectors/email.json @ 972ad43 — local knowledge base, not a Kibana build/test dependency. Keep in sync manually. */
export const emailDetector = {
  id: 'email',
  displayName: 'Email address',
  description:
    'Email addresses. Low difficulty and low false-positive rate using the predefined Grok email pattern; the cheap, reliable win in the set.',
  categories: ['PII'],
  detection: {
    grokPatterns: ['%{EMAILADDRESS:EMAIL}'],
    validation: {
      type: 'none',
    },
  },
  recommendedAction: 'remove',
  defaultPrecisionGuards: ['Redact anything matching a valid email address'],
  anticipatoryAffinity: ['us-ssn', 'visa', 'mastercard'],
};
