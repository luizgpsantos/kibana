/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { selectPreviewRecords } from './selectors';
import type { SimulationContext } from './types';

describe('selectPreviewRecords', () => {
  it('returns flattened sample documents when no preview filter is active', () => {
    const context = {
      samples: [{ document: { message: 'hello' } }],
      previewDocsFilter: undefined,
      simulation: undefined,
      selectedConditionId: undefined,
    } as unknown as Pick<
      SimulationContext,
      'samples' | 'previewDocsFilter' | 'simulation' | 'selectedConditionId'
    >;

    expect(selectPreviewRecords(context)).toEqual([{ message: 'hello' }]);
  });

  it('returns an empty array when samples is empty', () => {
    const context = {
      samples: [],
      previewDocsFilter: undefined,
      simulation: undefined,
      selectedConditionId: undefined,
    } as unknown as Pick<
      SimulationContext,
      'samples' | 'previewDocsFilter' | 'simulation' | 'selectedConditionId'
    >;

    expect(selectPreviewRecords(context)).toEqual([]);
  });
});
