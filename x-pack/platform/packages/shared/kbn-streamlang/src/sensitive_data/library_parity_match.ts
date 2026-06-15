/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { BASE_GROK_PATTERNS, compileGrokPatternToRegex } from '../../types/utils/grok_to_regex';
import { applyKeywordOverride } from './compile';
import { buildDefaultCategoryConfig, getDetectorById } from './catalog';

const GROK_REF = /%\{([A-Za-z0-9_]+)(?::[A-Za-z0-9_]+)?\}/g;

const resolveNestedPatterns = (
  pattern: string,
  definitions: Record<string, string>,
  seen: Set<string> = new Set()
): string =>
  pattern.replace(GROK_REF, (_match, name: string) => {
    if (seen.has(name)) {
      return _match;
    }
    const definition = definitions[name] ?? BASE_GROK_PATTERNS[name];
    if (!definition) {
      throw new Error(`library parity: missing pattern definition "${name}"`);
    }
    seen.add(name);
    const resolved = resolveNestedPatterns(definition, definitions, seen);
    seen.delete(name);
    return `(?:${resolved})`;
  });

/** Expand a keyword-gated grok pattern into a JavaScript RegExp for corpus tests. */
const keywordGatedGrokPatternToTestRegex = (
  grokPattern: string,
  definitions: Record<string, string>
): RegExp => {
  let pattern = resolveNestedPatterns(grokPattern, definitions);
  pattern = pattern.replace(/\\K/g, '');
  let flags = '';
  if (pattern.startsWith('(?i)')) {
    pattern = pattern.slice(4);
    flags = 'i';
  }
  // PCRE possessive `{n,m}+` → greedy `{n,m}` for JavaScript RegExp.
  pattern = pattern.replace(/\{(\d+),(\d+)\}\+/g, '{$1,$2}');
  return new RegExp(pattern, flags);
};

const grokPatternMatchesText = (
  grokPattern: string,
  definitions: Record<string, string>,
  text: string
): boolean => {
  if (grokPattern.includes('\\K') || grokPattern.startsWith('(?i)')) {
    return keywordGatedGrokPatternToTestRegex(grokPattern, definitions).test(text);
  }
  const compiled = compileGrokPatternToRegex(grokPattern, definitions);
  return compiled ? new RegExp(compiled.regex).test(text) : false;
};

/** Whether a catalog detector matches `text` using its default keyword configuration. */
export const detectorMatchesText = (detectorId: string, text: string): boolean => {
  const detector = getDetectorById(detectorId);
  if (!detector) {
    return false;
  }
  const config = buildDefaultCategoryConfig(detectorId);
  const configured = applyKeywordOverride(detector, config);
  const definitions = configured.detection.grokPatternDefinitions ?? {};
  return configured.detection.grokPatterns.some((grokPattern) =>
    grokPatternMatchesText(grokPattern, definitions, text)
  );
};
