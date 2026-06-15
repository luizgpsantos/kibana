/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import fs from 'fs';
import path from 'path';
import { detectorMatchesText } from './library_parity_match';

interface ParityCase {
  detectorId: string;
  text: string;
  shouldMatch: boolean;
}

const corpusPath = path.join(__dirname, '__fixtures__', 'library_parity_corpus.json');

describe('sensitive_data library parity corpus', () => {
  const cases = JSON.parse(fs.readFileSync(corpusPath, 'utf8')) as ParityCase[];

  it.each(cases)(
    '$detectorId on "$text" shouldMatch=$shouldMatch',
    ({ detectorId, text, shouldMatch }) => {
      expect(detectorMatchesText(detectorId, text)).toBe(shouldMatch);
    }
  );
});
