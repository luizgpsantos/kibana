/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/** Vendored from elastic-redact-pii/catalog/detectors/date-of-birth.json @ 972ad43 — local knowledge base, not a Kibana build/test dependency. Keep in sync manually. */
export const dateOfBirthDetector = {
  id: 'date-of-birth',
  displayName: 'Date of birth',
  description:
    "Dates of birth. A bare date pattern would eat every timestamp and log date, so this detector requires a date-of-birth keyword nearby. Accepts common numeric layouts (YYYY-MM-DD, MM/DD/YYYY, YYYYMMDD, MMDDYYYY) with -, /, ., or URL-encoded %2F separators, plus 'Month DD, YYYY'. The heaviest item in v1; expect tuning, and lean on the real-data preview.",
  categories: ['PII'],
  detection: {
    // The leading `(?=[dbDB])` lookahead lets the regex engine reject any position that cannot start
    // a keyword in a single character read, and the possessive quantifiers (`{0,15}+`, `\s++`) prevent
    // backtracking. Both keep the per-character scan cost low enough to stay under Elasticsearch's
    // Painless `script.painless.regex.limit-factor` ceiling when this runs as a script (tag/partial).
    grokPatterns: [
      '(?i)(?=[dbDB])(?:date of birth|d\\.?o\\.?b\\.?|birth ?date|\\bborn(?: on)?)[^0-9A-Za-z]{0,15}+\\K%{DOB:DOB}',
    ],
    grokPatternDefinitions: {
      DOB: '(?<![0-9])(?:[0-9]{4}(?:[-/.]|%2F)(?:0[1-9]|1[0-2])(?:[-/.]|%2F)(?:0[1-9]|[12][0-9]|3[01])|(?:0?[1-9]|1[0-2])(?:[-/.]|%2F)(?:0?[1-9]|[12][0-9]|3[01])(?:[-/.]|%2F)[0-9]{4}|[0-9]{4}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])|(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])[0-9]{4}|(?:January|February|March|April|May|June|July|August|September|October|November|December)\\s++[0-9]{1,2},?\\s++[0-9]{4})(?![0-9])',
    },
    validation: {
      type: 'none',
    },
  },
  recommendedAction: 'remove',
  defaultPrecisionGuards: [
    'Only treat a date as a birth date when labeled nearby',
    'Accept only conservative date formats',
  ],
  anticipatoryAffinity: ['us-ssn', 'email', 'passport-national-id'],
};
