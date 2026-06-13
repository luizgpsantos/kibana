/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Detector } from './catalog';

/**
 * Build the Java-regex used by the per-candidate confirmer from a checksum detector's grok pattern:
 * expand its `%{NAME:cap}` into a single capturing group `(def)` and drop `\K` (the value we replace
 * is group 1). Guards keep the group indexing and the Painless regex literal safe.
 */
export const confirmCandidateRegex = (detector: Detector): string => {
  const defs = detector.detection.grokPatternDefinitions || {};
  const pat = detector.detection.grokPatterns[0];
  let count = 0;
  let out = pat.replace(/%\{([A-Za-z0-9_]+)(?::[A-Za-z0-9_]+)?\}/g, (_m, name: string) => {
    const def = defs[name];
    if (!def) {
      throw new Error(
        `confirmed compile: ${detector.id} references %{${name}} with no pattern_definition`
      );
    }
    if (/\((?!\?)/.test(def)) {
      throw new Error(
        `confirmed compile: ${detector.id} value pattern has a capturing group; use (?:...)`
      );
    }
    count++;
    return `(${def})`;
  });
  if (count !== 1) {
    throw new Error(
      `confirmed compile: ${detector.id} needs exactly one value capture (found ${count})`
    );
  }
  out = out.replace(/\\K/g, '');
  // Painless uses `/pattern/` literals; escape slashes in the expanded value pattern.
  return out.replace(/\//g, '\\/');
};
