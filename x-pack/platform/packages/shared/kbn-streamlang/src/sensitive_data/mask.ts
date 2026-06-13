/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Detector } from './catalog';

const MASK_PREFIX = '<';
const MASK_SUFFIX = '>';

export const captureName = (detector: Detector): string | null => {
  const v = detector.detection.validation;
  if (v.appliesToField) {
    return v.appliesToField;
  }
  const joined = detector.detection.grokPatterns.join(' ');
  const matches = [...joined.matchAll(/%\{[^:}]+:([A-Za-z0-9_]+)\}/g)];
  return matches.length ? matches[matches.length - 1][1] : null;
};

export const maskToken = (detector: Detector): string =>
  `${MASK_PREFIX}${captureName(detector)}${MASK_SUFFIX}`;
