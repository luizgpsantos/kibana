/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

export const ipv6Detector = {
  id: 'ipv6',
  displayName: 'IPv6 address',
  description: 'IPv6 addresses in standard colon-hex notation.',
  categories: ['Network'],
  detection: {
    grokPatterns: ['%{IPV6:IPV6}'],
    grokPatternDefinitions: {},
    validation: {
      type: 'none',
    },
  },
  recommendedAction: 'redact',
  defaultPrecisionGuards: ['Redact IPv6 addresses'],
  anticipatoryAffinity: ['ipv4', 'mac-address'],
};
