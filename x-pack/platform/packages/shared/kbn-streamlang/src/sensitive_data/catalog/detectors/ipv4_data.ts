/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

export const ipv4Detector = {
  id: 'ipv4',
  displayName: 'IPv4 address',
  description: 'IPv4 addresses in dotted-decimal notation (0.0.0.0 – 255.255.255.255).',
  categories: ['Network', 'PII'],
  detection: {
    grokPatterns: ['%{IPV4:IPV4}'],
    grokPatternDefinitions: {},
    validation: {
      type: 'none',
    },
  },
  recommendedAction: 'redact',
  defaultPrecisionGuards: ['Redact IP addresses'],
  anticipatoryAffinity: ['ipv6', 'mac-address'],
};
