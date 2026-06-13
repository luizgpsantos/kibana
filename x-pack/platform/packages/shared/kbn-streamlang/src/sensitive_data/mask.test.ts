/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { getDetectorsByIds } from './catalog';
import { captureName, maskToken } from './mask';

describe('sensitive_data mask helpers', () => {
  it('derives the capture name and mask token from the active detector', () => {
    const [dob] = getDetectorsByIds(['date-of-birth']);
    expect(captureName(dob)).toBe('DOB');
    expect(maskToken(dob)).toBe('<DOB>');
  });
});
