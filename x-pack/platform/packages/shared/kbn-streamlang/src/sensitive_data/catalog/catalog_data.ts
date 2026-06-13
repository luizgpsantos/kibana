/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/** Vendored from elastic-redact-pii/catalog/catalog.json @ 972ad43 — local knowledge base, not a Kibana build/test dependency. Keep in sync manually. */
export const catalogIndexData = {
  name: 'Elastic Sensitive Data — detector catalog',
  version: '0.2.0',
  schema: 'schema/detector.schema.json',
  defaultPosture: 'opt-out',
  defaultAction: 'remove',
  detectors: [
    {
      id: 'credit-card',
      file: 'detectors/credit-card.json',
      displayName: 'Credit card number',
      categories: ['PCI DSS'],
      hero: true,
    },
    {
      id: 'us-ssn',
      file: 'detectors/us-ssn.json',
      displayName: 'US Social Security Number',
      categories: ['PII'],
      hero: true,
    },
    {
      id: 'email',
      file: 'detectors/email.json',
      displayName: 'Email address',
      categories: ['PII'],
    },
    {
      id: 'iban',
      file: 'detectors/iban.json',
      displayName: 'IBAN (bank account number)',
      categories: ['PII', 'Financial'],
    },
    {
      id: 'date-of-birth',
      file: 'detectors/date-of-birth.json',
      displayName: 'Date of birth',
      categories: ['PII'],
    },
    {
      id: 'passport-national-id',
      file: 'detectors/passport-national-id.json',
      displayName: 'Passport / national ID number',
      categories: ['PII'],
    },
    {
      id: 'national-id-ca-sin',
      file: 'detectors/national-id-ca-sin.json',
      displayName: 'Canadian Social Insurance Number',
      categories: ['PII'],
    },
  ],
  deferred: [],
  affinityVocabulary: [
    { slug: 'credit-card', displayName: 'Credit card number', detector: 'credit-card' },
    { slug: 'us-ssn', displayName: 'US Social Security Number', detector: 'us-ssn' },
    { slug: 'email', displayName: 'Email address', detector: 'email' },
    { slug: 'iban', displayName: 'IBAN (bank account number)', detector: 'iban' },
    { slug: 'date-of-birth', displayName: 'Date of birth', detector: 'date-of-birth' },
    {
      slug: 'passport-national-id',
      displayName: 'Passport / national ID number',
      detector: 'passport-national-id',
    },
    {
      slug: 'national-id-ca-sin',
      displayName: 'Canadian Social Insurance Number',
      detector: 'national-id-ca-sin',
    },
    { slug: 'cvv', displayName: 'Card verification value (CVV)', detector: null },
    { slug: 'cardholder-name', displayName: 'Cardholder name', detector: null },
    { slug: 'billing-address', displayName: 'Billing address', detector: null },
  ],
} as const;
