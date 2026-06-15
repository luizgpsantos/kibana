/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/** Avoid matching interface names like eth0:aa:bb:cc:dd:ee:ff — require a non-hex/non-colon prefix. */
const MAC_ADDR = '(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}[:\\-.]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])';

export const macAddressDetector = {
  id: 'mac-address',
  displayName: 'MAC address',
  description: 'Hardware MAC addresses in colon, hyphen, or dot notation.',
  categories: ['Network'],
  detection: {
    grokPatterns: ['%{MAC_ADDR:MAC_ADDR}'],
    grokPatternDefinitions: {
      MAC_ADDR,
    },
    validation: {
      type: 'none',
    },
  },
  recommendedAction: 'redact',
  defaultPrecisionGuards: ['Redact MAC addresses'],
  anticipatoryAffinity: ['ipv4', 'ipv6'],
};
