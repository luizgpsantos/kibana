/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { detectorHasValueCapture, getSupportedActionsForCategory } from './action_capabilities';
import { getDetectorsByIds } from './catalog';

describe('action capabilities', () => {
  it('limits email to full redact (no value capture for tag/partial)', () => {
    const [email] = getDetectorsByIds(['email']);
    expect(detectorHasValueCapture(email)).toBe(false);
    expect(getSupportedActionsForCategory('email')).toEqual(['redact']);
  });

  it('allows all actions for keyword-gated detectors with value capture', () => {
    expect(getSupportedActionsForCategory('visa')).toEqual(['redact', 'partial', 'tag']);
    expect(getSupportedActionsForCategory('us-ssn')).toEqual(['redact', 'partial', 'tag']);
    expect(getSupportedActionsForCategory('credit-card')).toEqual(['redact', 'partial', 'tag']);
  });
});
