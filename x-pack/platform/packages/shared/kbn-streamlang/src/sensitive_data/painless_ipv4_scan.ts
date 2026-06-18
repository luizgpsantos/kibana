/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Per-candidate IPv4 detection without regex.
 *
 * The IPv4 value regex (`(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}…`) is cheap in isolation,
 * but `matcher.find()` retries it at every offset, and on IP-dense input (network logs) every digit
 * offset is a plausible octet start. That keeps the char-visit ratio at ~6× regardless of possessive
 * quantifiers, so it trips `script.painless.regex.limit-factor` (verified against real ES). A linear
 * character scan visits each character a bounded number of times and removes the `matcher()` call
 * entirely, so the limit no longer applies — the same approach used for IPv6.
 */
export const IPV4_PER_CANDIDATE_SCAN_ID = 'ipv4';

/**
 * Opens a linear scan over `textVar` that yields `gs` and `ge` for each dotted-decimal IPv4 token
 * (four octets `0–255` joined by single dots, not adjacent to another digit/dot). Skips overlap
 * duplicates via `lastVar` (int, must exist in outer scope).
 */
export const painlessIpv4CandidateScanOpen = (
  textVar: string,
  lastVar: string,
  lengthVar: string = `${textVar}.length()`
): string[] => [
  `for (int i = 0; i < ${lengthVar}; i++) {`,
  `  char c0 = ${textVar}.charAt(i);`,
  `  if (c0 < (char)'0' || c0 > (char)'9') { continue; }`,
  // Start only at a token boundary — mirrors the regex's `(?<![0-9])` and rejects a leading dot so we
  // don't begin inside another address. This is what keeps the scan linear on IP-dense input.
  `  if (i > 0) { char pc = ${textVar}.charAt(i - 1); if ((pc >= (char)'0' && pc <= (char)'9') || pc == (char)'.') { continue; } }`,
  `  if (i < ${lastVar}) { continue; }`,
  `  int j = i;`,
  `  int octets = 0;`,
  `  boolean okShape = true;`,
  `  while (octets < 4) {`,
  `    int val = 0; int digits = 0;`,
  `    while (j < ${textVar}.length() && digits < 3) {`,
  `      char c = ${textVar}.charAt(j);`,
  `      if (c < (char)'0' || c > (char)'9') { break; }`,
  `      val = val * 10 + (c - (char)'0'); digits++; j++;`,
  `    }`,
  `    if (digits == 0 || val > 255) { okShape = false; break; }`,
  // A 4th digit on this octet (e.g. `1234`) is not a valid octet.
  `    if (j < ${textVar}.length() && ${textVar}.charAt(j) >= (char)'0' && ${textVar}.charAt(j) <= (char)'9') { okShape = false; break; }`,
  `    octets++;`,
  `    if (octets < 4) {`,
  `      if (j < ${textVar}.length() && ${textVar}.charAt(j) == (char)'.') { j++; } else { okShape = false; break; }`,
  `    }`,
  `  }`,
  `  if (!okShape || octets != 4) { continue; }`,
  // Reject a trailing dot+digit run (e.g. a 5-group address) — mirrors the regex's `(?![0-9])` tail.
  `  if (j < ${textVar}.length() && ${textVar}.charAt(j) == (char)'.') { continue; }`,
  `  int gs = i;`,
  `  int ge = j;`,
];

export const painlessIpv4CandidateScanClose = (lastVar: string, indexVar: string): string[] => [
  `  ${lastVar} = ge;`,
  `  ${indexVar} = ge - 1;`,
  `}`,
];
