/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { getSensitiveDataStepDescription, getStepDescription } from './utils';

describe('getSensitiveDataStepDescription', () => {
  it('describes a single configured category', () => {
    expect(getSensitiveDataStepDescription('message', [{ id: 'email' }])).toBe(
      'Redact 1 category from "message": Email address'
    );
  });

  it('lists multiple categories without truncation', () => {
    expect(
      getSensitiveDataStepDescription('body.text', [
        { id: 'email' },
        { id: 'ipv4' },
        { id: 'iban' },
      ])
    ).toBe(
      'Redact 3 categories from "body.text": Email address, IPv4 address, IBAN (bank account number)'
    );
  });

  it('truncates long category lists', () => {
    const description = getSensitiveDataStepDescription('message', [
      { id: 'email' },
      { id: 'visa' },
      { id: 'mastercard' },
      { id: 'amex' },
      { id: 'discover' },
      { id: 'ipv4' },
    ]);
    expect(description).toBe(
      'Redact 6 categories from "message": Email address, Visa card number, Mastercard number, American Express card number (+2 more)'
    );
  });

  it('handles no configured categories', () => {
    expect(getSensitiveDataStepDescription('message', [])).toBe(
      'Redact 0 categories from "message"'
    );
  });
});

describe('getStepDescription', () => {
  it('prefers a custom description for sensitive_data', () => {
    expect(
      getStepDescription({
        action: 'sensitive_data',
        from: 'message',
        categories: [{ id: 'email', action: 'redact' }],
        description: 'Custom summary',
        customIdentifier: 'step-1',
        parentId: null,
      })
    ).toBe('Custom summary');
  });

  it('does not JSON-serialize sensitive_data configuration', () => {
    const description = getStepDescription({
      action: 'sensitive_data',
      from: 'message',
      categories: [{ id: 'email', action: 'redact' }],
      customIdentifier: 'step-1',
      parentId: null,
    });
    expect(description).toBe('Redact 1 category from "message": Email address');
    expect(description).not.toContain('{');
  });
});
