/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/** Per-candidate IPv6 detection without regex — Painless regex cannot express IPv6 within scan limits. */
export const IPV6_PER_CANDIDATE_SCAN_ID = 'ipv6';

const isHexChar = (charVar: string): string =>
  `((${charVar} >= (char)'0' && ${charVar} <= (char)'9') || (${charVar} >= (char)'a' && ${charVar} <= (char)'f') || (${charVar} >= (char)'A' && ${charVar} <= (char)'F'))`;

/**
 * Opens a linear scan over `textVar` that yields `gs`, `ge`, and `cand` for each IPv6-like token.
 * Skips overlap duplicates via `lastVar` (int, must exist in outer scope).
 */
export const painlessIpv6CandidateScanOpen = (
  textVar: string,
  lastVar: string,
  lengthVar: string = `${textVar}.length()`
): string[] => [
  `for (int i = 0; i < ${lengthVar}; i++) {`,
  `  char c0 = ${textVar}.charAt(i);`,
  `  if (!(${isHexChar('c0')} || c0 == (char)':')) { continue; }`,
  `  int j = i;`,
  `  int colons = 0;`,
  `  boolean dcolon = false;`,
  `  while (j < ${textVar}.length()) {`,
  `    char c = ${textVar}.charAt(j);`,
  `    if (${isHexChar('c')}) { j++; continue; }`,
  `    if (c == (char)':') {`,
  `      if (j + 1 < ${textVar}.length() && ${textVar}.charAt(j + 1) == (char)':') {`,
  `        if (dcolon) { break; }`,
  `        dcolon = true;`,
  `        j += 2;`,
  `        continue;`,
  `      }`,
  `      colons++;`,
  `      j++;`,
  `      continue;`,
  `    }`,
  `    break;`,
  `  }`,
  `  if (j <= i) { continue; }`,
  `  boolean onlyTwoHexGroups = true;`,
  `  int p = i;`,
  `  while (p < j) {`,
  `    if (p + 2 > j || !${isHexChar(`${textVar}.charAt(p)`)} || !${isHexChar(
    `${textVar}.charAt(p + 1)`
  )} ) { onlyTwoHexGroups = false; break; }`,
  `    if (p + 2 == j) { break; }`,
  `    if (${textVar}.charAt(p + 2) != (char)':') { onlyTwoHexGroups = false; break; }`,
  `    p += 3;`,
  `  }`,
  `  if (onlyTwoHexGroups && colons >= 2) { continue; }`,
  `  if (!dcolon && colons < 2) { continue; }`,
  `  int gs = i;`,
  `  int ge = j;`,
  `  if (gs < ${lastVar}) { continue; }`,
];

export const painlessIpv6CandidateScanClose = (lastVar: string, indexVar: string): string[] => [
  `  ${lastVar} = ge;`,
  `  ${indexVar} = ge - 1;`,
  `}`,
];
