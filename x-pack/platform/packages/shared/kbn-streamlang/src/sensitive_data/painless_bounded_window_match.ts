/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Bounded-window matcher for digit-boundary value patterns (payment cards, US SSN, legacy
 * credit-card).
 *
 * These detectors keep their exact brand regex — IIN prefix + grouped digits with optional single
 * separators — because the regex *is* the detector (most are `validation: none`, no checksum). The
 * problem is only how the regex is driven: `matcher.find()` over a 128-char chunk retries at every
 * offset and backtracks over the `[ .-]?` separators, so separator-dense input trips
 * `script.painless.regex.limit-factor`.
 *
 * Instead we scan linearly for a candidate *start* — a digit at a `(?<![0-9])` boundary — and run the
 * brand regex with `matcher.lookingAt()` against a short fixed window starting there. A payment card
 * is at most 19 digits plus 18 separators (37 chars), so a {@link BOUNDED_MATCH_WINDOW}-char window
 * always contains a full candidate, and each matcher operation sees a bounded input whose budget
 * (`limit-factor × windowLength`) comfortably covers the bounded backtracking. Verified against real
 * ES: stays under budget on the adversarial digit-dense matrix input while matching exactly what the
 * chunked `find()` matched. The regex must wrap the value as group 1 (as `confirmCandidateRegex`
 * emits) and begin with its `(?<![0-9])` boundary — the lookbehind is vacuously satisfied at the
 * window start, and the scan's own boundary check enforces it.
 */
export const BOUNDED_MATCH_WINDOW = 64;

/**
 * Opens a bounded-window scan over `textVar`. Yields global `gs`, `ge`, and `cand` (group 1) per
 * match. Skips overlap duplicates via `lastVar` (int, must exist in outer scope).
 */
export const painlessBoundedWindowLoopOpen = (
  regex: string,
  textVar: string,
  lastVar: string,
  lengthVar: string = `${textVar}.length()`
): string[] => [
  `for (int i = 0; i < ${lengthVar}; i++) {`,
  `  char c0 = ${textVar}.charAt(i);`,
  `  if (c0 < (char)'0' || c0 > (char)'9') { continue; }`,
  `  if (i > 0) { char pc = ${textVar}.charAt(i - 1); if (pc >= (char)'0' && pc <= (char)'9') { continue; } }`,
  `  if (i < ${lastVar}) { continue; }`,
  `  int __we = i + ${BOUNDED_MATCH_WINDOW};`,
  `  if (__we > ${textVar}.length()) { __we = ${textVar}.length(); }`,
  `  String __w = ${textVar}.substring(i, __we);`,
  `  def __m = /${regex}/.matcher(__w);`,
  `  if (!__m.lookingAt()) { continue; }`,
  `  int gs = i;`,
  `  int ge = i + __m.end(1);`,
  `  String cand = __m.group(1);`,
];

export const painlessBoundedWindowLoopClose = (lastVar: string, indexVar: string): string[] => [
  `  ${lastVar} = ge;`,
  `  ${indexVar} = ge - 1;`,
  `}`,
];

/**
 * Bounded-window variant that stops at the first match (tag-only telemetry detection). Yields `gs`
 * for the matched candidate before running `breakCondition`.
 */
export const painlessBoundedWindowAnyFindOpen = (
  regex: string,
  textVar: string,
  lengthVar: string = `${textVar}.length()`
): string[] => [
  `for (int i = 0; i < ${lengthVar}; i++) {`,
  `  char c0 = ${textVar}.charAt(i);`,
  `  if (c0 < (char)'0' || c0 > (char)'9') { continue; }`,
  `  if (i > 0) { char pc = ${textVar}.charAt(i - 1); if (pc >= (char)'0' && pc <= (char)'9') { continue; } }`,
  `  int __we = i + ${BOUNDED_MATCH_WINDOW};`,
  `  if (__we > ${textVar}.length()) { __we = ${textVar}.length(); }`,
  `  String __w = ${textVar}.substring(i, __we);`,
  `  def __m = /${regex}/.matcher(__w);`,
  `  if (!__m.lookingAt()) { continue; }`,
  `  int gs = i;`,
];

export const painlessBoundedWindowAnyFindClose = (breakCondition: string): string[] => [
  `  ${breakCondition}`,
  `  break;`,
  `}`,
];
