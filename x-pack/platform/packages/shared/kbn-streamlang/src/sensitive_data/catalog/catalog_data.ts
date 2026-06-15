/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/** Vendored from elastic-redact-pii/catalog/catalog.json @ 972ad43 — local knowledge base, not a Kibana build/test dependency. Keep in sync manually. */
export const catalogIndexData = {
  name: 'Elastic Sensitive Data — detector catalog',
  version: '0.4.0',
  schema: 'schema/detector.schema.json',
  defaultPosture: 'opt-out',
  defaultAction: 'remove',
  detectors: [
    {
      id: 'visa',
      file: 'detectors/visa.json',
      displayName: 'Visa card number',
      categories: ['PCI DSS'],
    },
    {
      id: 'mastercard',
      file: 'detectors/mastercard.json',
      displayName: 'Mastercard number',
      categories: ['PCI DSS'],
    },
    {
      id: 'amex',
      file: 'detectors/amex.json',
      displayName: 'American Express card number',
      categories: ['PCI DSS'],
    },
    {
      id: 'discover',
      file: 'detectors/discover.json',
      displayName: 'Discover card number',
      categories: ['PCI DSS'],
    },
    {
      id: 'diners',
      file: 'detectors/diners.json',
      displayName: 'Diners Club card number',
      categories: ['PCI DSS'],
    },
    {
      id: 'jcb',
      file: 'detectors/jcb.json',
      displayName: 'JCB card number',
      categories: ['PCI DSS'],
    },
    {
      id: 'maestro',
      file: 'detectors/maestro.json',
      displayName: 'Maestro card number',
      categories: ['PCI DSS'],
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
      id: 'ipv4',
      file: 'detectors/ipv4.json',
      displayName: 'IPv4 address',
      categories: ['Network', 'PII'],
    },
    {
      id: 'ipv6',
      file: 'detectors/ipv6.json',
      displayName: 'IPv6 address',
      categories: ['Network'],
    },
    {
      id: 'mac-address',
      file: 'detectors/mac-address.json',
      displayName: 'MAC address',
      categories: ['Network'],
    },
  ],
  deferred: [{ id: 'date-of-birth', file: 'detectors/date-of-birth.json' }],
  affinityVocabulary: [
    { slug: 'visa', displayName: 'Visa card number', detector: 'visa' },
    { slug: 'mastercard', displayName: 'Mastercard number', detector: 'mastercard' },
    { slug: 'amex', displayName: 'American Express card number', detector: 'amex' },
    { slug: 'discover', displayName: 'Discover card number', detector: 'discover' },
    { slug: 'diners', displayName: 'Diners Club card number', detector: 'diners' },
    { slug: 'jcb', displayName: 'JCB card number', detector: 'jcb' },
    { slug: 'maestro', displayName: 'Maestro card number', detector: 'maestro' },
    { slug: 'us-ssn', displayName: 'US Social Security Number', detector: 'us-ssn' },
    { slug: 'email', displayName: 'Email address', detector: 'email' },
    { slug: 'iban', displayName: 'IBAN (bank account number)', detector: 'iban' },
    { slug: 'ipv4', displayName: 'IPv4 address', detector: 'ipv4' },
    { slug: 'ipv6', displayName: 'IPv6 address', detector: 'ipv6' },
    { slug: 'mac-address', displayName: 'MAC address', detector: 'mac-address' },
  ],
} as const;
