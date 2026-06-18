/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Max input length per `matcher.find()` call. Elasticsearch enforces
 * `script.painless.regex.limit-factor` × inputLength character visits (default factor 6).
 * Small chunks keep structural detectors (email, IPv6, etc.) under the ceiling on long log lines.
 */
export const PAINLESS_MATCHER_CHUNK_SIZE = 128;

/** Overlap between consecutive chunks so tokens spanning a boundary are still found whole. */
export const PAINLESS_MATCHER_CHUNK_OVERLAP = 64;

/**
 * Opens a chunked scan loop over `textVar`. Yields global `gs`, `ge`, and `cand` (group 1) per match.
 * Skips overlap duplicates via `lastVar` (int, must exist in outer scope). `lengthVar` bounds where new
 * matches may *start* (defaults to the full length; pass a capped length for the input-size guardrail).
 */
export const painlessChunkedMatcherLoopOpen = (
  regex: string,
  textVar: string,
  lastVar: string,
  lengthVar: string = `${textVar}.length()`
): string[] => {
  const step = PAINLESS_MATCHER_CHUNK_SIZE - PAINLESS_MATCHER_CHUNK_OVERLAP;
  return [
    `for (int __off = 0; __off < ${lengthVar}; __off += ${step}) {`,
    `  int __end = __off + ${PAINLESS_MATCHER_CHUNK_SIZE};`,
    `  if (__end > ${textVar}.length()) { __end = ${textVar}.length(); }`,
    `  String __slice = ${textVar}.substring(__off, __end);`,
    `  def __m = /${regex}/.matcher(__slice);`,
    `  while (__m.find()) {`,
    `    int gs = __off + __m.start(1);`,
    `    int ge = __off + __m.end(1);`,
    `    if (gs < ${lastVar}) { continue; }`,
    `    String cand = __m.group(1);`,
  ];
};

export const painlessChunkedMatcherLoopClose = (): string[] => [`  }`, `}`];

/** Chunked scan that stops at the first successful match (tag-only telemetry detection). */
export const painlessChunkedMatcherAnyFindOpen = (
  regex: string,
  textVar: string,
  lengthVar: string = `${textVar}.length()`
): string[] => {
  const step = PAINLESS_MATCHER_CHUNK_SIZE - PAINLESS_MATCHER_CHUNK_OVERLAP;
  return [
    `for (int __off = 0; __off < ${lengthVar}; __off += ${step}) {`,
    `  int __end = __off + ${PAINLESS_MATCHER_CHUNK_SIZE};`,
    `  if (__end > ${textVar}.length()) { __end = ${textVar}.length(); }`,
    `  String __slice = ${textVar}.substring(__off, __end);`,
    `  def __m = /${regex}/.matcher(__slice);`,
    `  if (__m.find()) {`,
    `    int gs = __off + __m.start(1);`,
  ];
};

export const painlessChunkedMatcherAnyFindClose = (breakCondition: string): string[] => [
  `    ${breakCondition}`,
  `    break;`,
  `  }`,
  `}`,
];
