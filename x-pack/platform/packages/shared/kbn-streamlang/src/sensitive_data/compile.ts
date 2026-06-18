/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { IngestProcessorContainer } from '@elastic/elasticsearch/lib/api/types';
import type { SensitiveDataCategory } from '../../types/processors';
import { painlessFieldAccessor, painlessFieldAssignment } from '../../types/utils';
import { normalizeCategoryActionForCompile } from './action_capabilities';
import type { Detector } from './catalog';
import { getDetectorById, getDefaultKeywordProximity, requiresKeywordProximity } from './catalog';
import { confirmCandidateRegex } from './confirm_candidate_regex';
import { hashCandidateRegex, painlessAssignFingerprintFromRange } from './hash_fingerprint';
import {
  IPV6_PER_CANDIDATE_SCAN_ID,
  painlessIpv6CandidateScanClose,
  painlessIpv6CandidateScanOpen,
} from './painless_ipv6_scan';
import {
  IPV4_PER_CANDIDATE_SCAN_ID,
  painlessIpv4CandidateScanClose,
  painlessIpv4CandidateScanOpen,
} from './painless_ipv4_scan';
import {
  detectorForScriptRegex,
  painlessKeywordProximityGuard,
} from './keyword_proximity_painless';
import {
  painlessChunkedMatcherAnyFindClose,
  painlessChunkedMatcherAnyFindOpen,
  painlessChunkedMatcherLoopClose,
  painlessChunkedMatcherLoopOpen,
} from './painless_chunked_regex_match';
import {
  painlessBoundedWindowAnyFindClose,
  painlessBoundedWindowAnyFindOpen,
  painlessBoundedWindowLoopClose,
  painlessBoundedWindowLoopOpen,
} from './painless_bounded_window_match';
import { captureName, maskToken } from './mask';

/**
 * How a per-candidate transform (`hash`/`partial`/`tag`/checksum-`redact`) iterates matches over the
 * field. Regex-driven detectors that re-scan characters trip `script.painless.regex.limit-factor`, so
 * detectors whose value pattern is unsafe under `matcher.find()` use a linear scan or a bounded-window
 * matcher instead — all four kinds expose the same `gs`/`ge`/`cand` + `last` contract to the body.
 */
type CandidateLoopKind = 'chunked' | 'ipv6-scan' | 'ipv4-scan' | 'digit-window';

const candidateLoopKind = (detectorId: string, regex: string): CandidateLoopKind => {
  if (detectorId === IPV6_PER_CANDIDATE_SCAN_ID) return 'ipv6-scan';
  if (detectorId === IPV4_PER_CANDIDATE_SCAN_ID) return 'ipv4-scan';
  // Digit-boundary value patterns (payment cards, US SSN, legacy credit-card) wrap the value as
  // group 1 and begin with a `(?<![0-9])` boundary. `matcher.find()` over a chunk backtracks on their
  // `[ .-]?` separators and trips the limit on separator-dense input, so drive them with a
  // bounded-window matcher that keeps the exact brand regex but bounds the matcher input.
  if (regex.startsWith('((?<![0-9])')) return 'digit-window';
  return 'chunked';
};

/**
 * Hard cap on how many characters of a field any per-candidate Painless scan will inspect for new
 * match starts. A single multi-megabyte field would otherwise dominate an ingest node even with a
 * linear scan; PII is virtually never past 32 KB into one field. Characters beyond the cap are copied
 * through unchanged (never redacted/hashed) and, when telemetry is on, the document is flagged
 * `<namespace>.truncated`. This is an absolute-cost guardrail (Spec 03), independent of the
 * regex-limit fixes — it never substitutes for keeping a detector low-ratio.
 */
export const MAX_SCAN_CHARS = 32768;

/** Opens the per-candidate loop, declaring `gs`/`ge` (+ `cand` group 1 for value-matching kinds). */
const perCandidateLoopOpen = (
  kind: CandidateLoopKind,
  regex: string,
  textVar: string,
  lastVar: string,
  lengthVar: string
): string[] => {
  switch (kind) {
    case 'ipv6-scan':
      return painlessIpv6CandidateScanOpen(textVar, lastVar, lengthVar);
    case 'ipv4-scan':
      return painlessIpv4CandidateScanOpen(textVar, lastVar, lengthVar);
    case 'digit-window':
      return painlessBoundedWindowLoopOpen(regex, textVar, lastVar, lengthVar);
    case 'chunked':
      return painlessChunkedMatcherLoopOpen(regex, textVar, lastVar, lengthVar);
  }
};

/**
 * Declares `int __scanLen` capping new-match scanning at {@link MAX_SCAN_CHARS} characters of `textVar`.
 * A ternary is used rather than `Math.min` because Painless resolves `Math.min(int, int)` to the
 * `double` overload, which cannot be assigned back to an `int`.
 */
const scanLenDecl = (textVar: string): string =>
  `int __scanLen = ${textVar}.length() < ${MAX_SCAN_CHARS} ? ${textVar}.length() : ${MAX_SCAN_CHARS};`;

/**
 * Sets `<flagNamespace>.truncated = true` when `textVar` was longer than the scan cap. Emitted only
 * with telemetry on; the field's content (including the un-scanned tail) is preserved regardless.
 */
const truncationFlagLine = (textVar: string, flagReport?: FlagReportOptions): string[] =>
  flagReport?.withFlags === true
    ? [
        `if (${textVar}.length() > __scanLen) { ${painlessFieldAssignment(
          `${flagReport.flagNamespace}.truncated`
        )} = true; }`,
      ]
    : [];

/** Closes the per-candidate loop, emitting `last = ge;` (+ index advance for scans) and braces. */
const perCandidateLoopClose = (kind: CandidateLoopKind, lastVar: string): string[] => {
  switch (kind) {
    case 'ipv6-scan':
      return painlessIpv6CandidateScanClose(lastVar, 'i');
    case 'ipv4-scan':
      return painlessIpv4CandidateScanClose(lastVar, 'i');
    case 'digit-window':
      return painlessBoundedWindowLoopClose(lastVar, 'i');
    case 'chunked':
      return [`    ${lastVar} = ge;`, ...painlessChunkedMatcherLoopClose()];
  }
};

export { confirmCandidateRegex } from './confirm_candidate_regex';

export { captureName, maskToken } from './mask';

const CHECKSUM_TYPES = ['luhn', 'mod97', 'painless'] as const;

export interface CompileOptions {
  field?: string;
  /**
   * Append the telemetry flag script: on a redacted document, set `<flagNamespace>.detected` and
   * `<flagNamespace>.categories` (the detector ids that fired) so dashboards can aggregate masking.
   */
  withFlags?: boolean;
  /**
   * Dotted object path the telemetry flags are written to. Defaults to `sensitive_data` (an ECS
   * custom field set). Streams following the OTel convention pass `attributes.sensitive_data` so the
   * flags land in a sanctioned namespace.
   */
  flagNamespace?: string;
  /**
   * Legacy shape: one structural `redact` over ALL patterns, pattern-only (no checksum
   * confirmation — over-redacts numeric IDs but never leaks). Defaults to `false`: the confirmed
   * engine runs a per-candidate checksum confirmer for checksum detectors.
   */
  structuralOnly?: boolean;
}

export const DEFAULT_FLAG_NAMESPACE = 'sensitive_data';

export const isChecksum = (detector: Detector): boolean =>
  (CHECKSUM_TYPES as readonly string[]).includes(detector.detection.validation.type);

interface DetectorToken {
  id: string;
  displayName: string;
  captureName: string | null;
  token: string;
}

const detectorTokens = (detectors: Detector[]): DetectorToken[] =>
  detectors.map((d) => ({
    id: d.id,
    displayName: d.displayName || d.id,
    captureName: captureName(d),
    token: maskToken(d),
  }));

export interface CategoryCompileEntry {
  detector: Detector;
  config: SensitiveDataCategory;
}

const escapeRegexKeyword = (keyword: string): string =>
  keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Escape a value for safe embedding in a single-quoted Painless string literal. */
const painlessSingleQuoted = (value: string): string =>
  value.replace(/\\/g, '\\\\').replace(/'/g, "\\'");

/**
 * Cheap leading lookahead so the keyword alternation is only attempted at positions that could start
 * a keyword, instead of running every branch at every character. This keeps the Painless regex
 * char-scan well under Elasticsearch's `script.painless.regex.limit-factor` ceiling. Only emitted
 * when every keyword starts with an ASCII letter (otherwise a safe character class can't be built).
 */
const keywordFirstCharGate = (keywords: string[]): string => {
  const firstChars = keywords.map((k) => k.trim().charAt(0)).filter((c) => c.length > 0);
  if (firstChars.length === 0 || !firstChars.every((c) => /[A-Za-z]/.test(c))) {
    return '';
  }
  const variants = new Set<string>();
  for (const c of firstChars) {
    variants.add(c.toLowerCase());
    variants.add(c.toUpperCase());
  }
  return `(?=[${Array.from(variants).join('')}])`;
};

/** Override proximity keywords on keyword-gated detectors (DOB, US SSN). */
export const applyKeywordOverride = (
  detector: Detector,
  config: SensitiveDataCategory
): Detector => {
  if (!config.keywords?.length || !requiresKeywordProximity(detector.id)) {
    return detector;
  }
  const proximity = config.keywordProximity ?? getDefaultKeywordProximity(detector.id) ?? 30;
  const keywordAlt = config.keywords.map(escapeRegexKeyword).join('|');
  const gate = keywordFirstCharGate(config.keywords);
  const prefix = `(?i)${gate}(?:${keywordAlt})[^0-9A-Za-z]{0,${proximity}}+\\K`;
  const applyToPattern = (pat: string): string => {
    const kIndex = pat.indexOf('\\K');
    if (kIndex < 0) {
      return prefix + pat;
    }
    // Detectors already anchor with `\K`; drop it so we do not emit `\K\K` before the grok capture.
    return prefix + pat.slice(kIndex + 2);
  };
  return {
    ...detector,
    detection: {
      ...detector.detection,
      grokPatterns: detector.detection.grokPatterns.map(applyToPattern),
    },
  };
};

export interface ResolveCategoryEntriesResult {
  entries: CategoryCompileEntry[];
  warnings: string[];
}

export const resolveCategoryEntries = (
  categories: SensitiveDataCategory[]
): ResolveCategoryEntriesResult => {
  const warnings: string[] = [];
  const entries: CategoryCompileEntry[] = [];

  for (const config of categories) {
    const detector = getDetectorById(config.id);
    if (!detector) {
      warnings.push(`Unknown sensitive-data category "${config.id}"; skipping.`);
      continue;
    }
    const detectorWithKeywords = applyKeywordOverride(detector, config);
    const { config: normalizedConfig, warning } = normalizeCategoryActionForCompile(
      config,
      detectorWithKeywords
    );
    if (warning) {
      warnings.push(warning);
    }
    if (
      requiresKeywordProximity(config.id) &&
      !normalizedConfig.keywords?.length &&
      normalizedConfig.useRecommendedKeywords !== true
    ) {
      warnings.push(
        `Category "${config.id}": keyword proximity is recommended; matches may include false positives without nearby keywords.`
      );
    }
    entries.push({ config: normalizedConfig, detector: detectorWithKeywords });
  }

  return { entries, warnings };
};

export const tokenForCategory = (detector: Detector, config: SensitiveDataCategory): string =>
  config.maskToken ?? maskToken(detector);

interface FlagReportOptions {
  withFlags: boolean;
  flagNamespace: string;
}

/** Merge `detectorId` into `<flagNamespace>.categories` and set `detected` (dedup, no clobber). */
const mergeSensitiveCategoryReport = (detectorId: string, flagNamespace: string): string =>
  [
    `def __existing = ${painlessFieldAssignment(`${flagNamespace}.categories`)};`,
    `ArrayList __cats = new ArrayList();`,
    `if (__existing instanceof List) {`,
    `  for (def __item : __existing) {`,
    `    if (__item instanceof String && !__cats.contains(__item)) { __cats.add(__item); }`,
    `  }`,
    `}`,
    `if (!__cats.contains('${detectorId}')) { __cats.add('${detectorId}'); }`,
    `${painlessFieldAssignment(`${flagNamespace}.detected`)} = true;`,
    `${painlessFieldAssignment(`${flagNamespace}.categories`)} = __cats;`,
  ].join('\n');

const flagCategoriesInitLines = (flagNamespace: string): string[] => [
  `def __existing = ${painlessFieldAssignment(`${flagNamespace}.categories`)};`,
  `ArrayList cats = new ArrayList();`,
  `if (__existing instanceof List) {`,
  `  for (def __item : __existing) {`,
  `    if (__item instanceof String && !cats.contains(__item)) { cats.add(__item); }`,
  `  }`,
  `}`,
];

/**
 * Telemetry post-script. Reads the (possibly dotted/flat-key) target field via the flexible
 * accessor, and on a redacted document records the masking outcome as structured fields under
 * `flagNamespace`: `<ns>.detected` (boolean) and `<ns>.categories` (the detector ids). The
 * namespace is written as a single flat key (e.g. `ctx['attributes.sensitive_data.detected']`) to
 * stay consistent with the flexible field access pattern Streams uses. The script short-circuits in
 * its body when no mask token is present so it can carry the step's `where` condition as its `if`.
 */
const flagScript = (
  detectors: Detector[],
  field: string,
  flagNamespace: string
): IngestProcessorContainer => {
  const tokens = detectorTokens(detectors);
  const lines = [
    `def value = ${painlessFieldAccessor(field)};`,
    `if (!(value instanceof String)) { return; }`,
    `String f = (String) value;`,
    `ArrayList cats = new ArrayList();`,
  ];
  for (const t of tokens) {
    lines.push(`if (f.indexOf('${t.token}') >= 0) { cats.add('${t.id}'); }`);
  }
  lines.push(
    `if (!cats.isEmpty()) {`,
    `  ${painlessFieldAssignment(`${flagNamespace}.detected`)} = true;`,
    `  ${painlessFieldAssignment(`${flagNamespace}.categories`)} = cats;`,
    `}`
  );
  return {
    script: {
      lang: 'painless',
      description: `Record ${flagNamespace}.detected and ${flagNamespace}.categories from mask tokens`,
      source: lines.join('\n'),
    },
  } as IngestProcessorContainer;
};

/**
 * Final telemetry pass: structural redact (default mask token) and tag-only regex.
 * Checksum redact and partial actions self-report in their transform scripts.
 */
const flagScriptFromEntries = (
  entries: CategoryCompileEntry[],
  field: string,
  flagNamespace: string
): IngestProcessorContainer => {
  // Tag entries run a per-candidate Painless scan over the field, so they get the same scan cap as
  // hash/partial; structural-redact entries below only do a literal `indexOf` and are not capped.
  const hasTagScan = entries.some((e) => e.config.action === 'tag');
  const lines = [
    `def value = ${painlessFieldAccessor(field)};`,
    `if (!(value instanceof String)) { return; }`,
    `String f = (String) value;`,
    ...(hasTagScan ? [scanLenDecl('f')] : []),
    ...flagCategoriesInitLines(flagNamespace),
  ];
  for (const entry of entries) {
    const { detector, config } = entry;
    if (config.action === 'partial' || config.action === 'hash') {
      continue;
    }
    if (config.action === 'tag') {
      const scriptDetector = detectorForScriptRegex(detector, config);
      const regex = confirmCandidateRegex(scriptDetector);
      const kind = candidateLoopKind(detector.id, regex);
      const anyFindOpen =
        kind === 'digit-window'
          ? painlessBoundedWindowAnyFindOpen
          : painlessChunkedMatcherAnyFindOpen;
      const anyFindClose =
        kind === 'digit-window'
          ? painlessBoundedWindowAnyFindClose
          : painlessChunkedMatcherAnyFindClose;
      const keywordGuard = painlessKeywordProximityGuard(config, 'f', 'gs');
      if (keywordGuard) {
        lines.push(
          ...anyFindOpen(regex, 'f', '__scanLen'),
          ...keywordGuard.split('\n').map((line) => `    ${line}`),
          ...anyFindClose(
            `if (kwOk && !cats.contains('${detector.id}')) { cats.add('${detector.id}'); }`
          )
        );
      } else {
        lines.push(
          ...anyFindOpen(regex, 'f', '__scanLen'),
          ...anyFindClose(`if (!cats.contains('${detector.id}')) { cats.add('${detector.id}'); }`)
        );
      }
      continue;
    }
    if (config.action === 'redact' && isChecksum(detector)) {
      continue;
    }
    const defaultToken = maskToken(detector);
    lines.push(
      `if (f.indexOf('${defaultToken}') >= 0 && !cats.contains('${detector.id}')) { cats.add('${detector.id}'); }`
    );
  }
  lines.push(
    `if (!cats.isEmpty()) {`,
    `  ${painlessFieldAssignment(`${flagNamespace}.detected`)} = true;`,
    `  ${painlessFieldAssignment(`${flagNamespace}.categories`)} = cats;`,
    `}`
  );
  if (hasTagScan) {
    lines.push(
      `if (f.length() > __scanLen) { ${painlessFieldAssignment(
        `${flagNamespace}.truncated`
      )} = true; }`
    );
  }
  return {
    script: {
      lang: 'painless',
      description: `Record ${flagNamespace}.detected and ${flagNamespace}.categories`,
      source: lines.join('\n'),
    },
  } as IngestProcessorContainer;
};

const combinedRedactProcessor = (
  detectors: Detector[],
  field: string,
  description: string
): IngestProcessorContainer => {
  const patterns: string[] = [];
  const defs: Record<string, string> = {};
  for (const det of detectors) {
    for (const p of det.detection.grokPatterns) patterns.push(p);
    Object.assign(defs, det.detection.grokPatternDefinitions || {});
  }
  return {
    redact: { field, patterns, pattern_definitions: defs, ignore_missing: true, description },
  } as IngestProcessorContainer;
};

/** Inline Painless that sets `boolean ok` from `String cand` for a checksum type. */
const checksumBody = (type: string): string => {
  if (type === 'luhn') {
    // Length is enforced by the candidate regex; reject uniform-digit candidates (Luhn-trivial).
    return [
      'int sum = 0; boolean alt = false; int cnt = 0; int first = -1; boolean multi = false;',
      "for (int __ci = cand.length() - 1; __ci >= 0; __ci--) { char c = cand.charAt(__ci); if (c < (char)'0' || c > (char)'9') { continue; } int raw = c - (char)'0'; if (first < 0) { first = raw; } else if (raw != first) { multi = true; } int d = raw; cnt++; if (alt) { d *= 2; if (d > 9) { d -= 9; } } sum += d; alt = !alt; }",
      'boolean ok = (cnt > 0 && multi && sum % 10 == 0);',
    ].join(' ');
  }
  if (type === 'mod97') {
    return [
      "String s = '';",
      "for (int __ci = 0; __ci < cand.length(); __ci++) { char c = cand.charAt(__ci); if (c == (char)' ') { continue; } if (c >= (char)'a' && c <= (char)'z') { c = (char)(c - 32); } s += c; }",
      'boolean ok;',
      'if (s.length() < 15 || s.length() > 34) { ok = false; } else {',
      'String rearr = s.substring(4) + s.substring(0, 4); long rem = 0; boolean good = true;',
      "for (int __ci = 0; __ci < rearr.length(); __ci++) { char c = rearr.charAt(__ci); int val; if (c >= (char)'0' && c <= (char)'9') { val = c - (char)'0'; rem = (rem * 10 + val) % 97; } else if (c >= (char)'A' && c <= (char)'Z') { val = c - (char)'A' + 10; rem = (rem * 100 + val) % 97; } else { good = false; break; } }",
      'ok = good && (rem == 1); }',
    ].join(' ');
  }
  throw new Error(
    `confirmed compile: unsupported checksum type "${type}" for per-candidate confirmation`
  );
};

/**
 * Per-candidate confirmer for one checksum detector: a single pass over `field` with one compiled
 * matcher, validating each candidate independently and replacing ONLY the passing ones with the
 * mask token (a valid card never drags an adjacent invalid one with it). One `script` processor per
 * checksum detector — far cheaper than a grok → script → redact → remove chain per detector.
 */
export const confirmScript = (
  detector: Detector,
  field: string,
  replacementToken?: string,
  flagReport?: FlagReportOptions
): IngestProcessorContainer => {
  const token = replacementToken ?? maskToken(detector);
  // Single-quote escape required: user-supplied tokens are embedded in a Painless string literal.
  // partialRedactScript applies the same escape via maskPrefix; keep these two in sync.
  const escapedToken = painlessSingleQuoted(token);
  const regex = confirmCandidateRegex(detector);
  const kind = candidateLoopKind(detector.id, regex);
  const type = detector.detection.validation.type;
  const reportOnAny =
    flagReport?.withFlags === true
      ? [
          `  out += text.substring(last);`,
          `  ${painlessFieldAssignment(field)} = out;`,
          mergeSensitiveCategoryReport(detector.id, flagReport.flagNamespace),
        ]
      : [`  out += text.substring(last); ${painlessFieldAssignment(field)} = out;`];
  const source = [
    `def value = ${painlessFieldAccessor(field)};`,
    `if (!(value instanceof String)) { return; }`,
    `String text = (String) value;`,
    `String out = ''; int last = 0; boolean any = false;`,
    scanLenDecl('text'),
    ...perCandidateLoopOpen(kind, regex, 'text', 'last', '__scanLen'),
    `    ${checksumBody(type)}`,
    `    out += text.substring(last, gs);`,
    `    if (ok) { out += '${escapedToken}'; any = true; } else { out += text.substring(gs, ge); }`,
    ...perCandidateLoopClose(kind, 'last'),
    `if (any) {`,
    ...reportOnAny,
    `}`,
    ...truncationFlagLine('text', flagReport),
  ].join('\n');
  return {
    script: {
      lang: 'painless',
      description: `Redact confirmed ${detector.displayName} — per-candidate ${type} checksum`,
      source,
    },
  } as IngestProcessorContainer;
};

const partialRedactScript = (
  entry: CategoryCompileEntry,
  field: string,
  flagReport?: FlagReportOptions
): IngestProcessorContainer => {
  const scriptDetector = detectorForScriptRegex(entry.detector, entry.config);
  const regex = confirmCandidateRegex(scriptDetector);
  const kind = candidateLoopKind(entry.detector.id, regex);
  const keywordGuard =
    painlessKeywordProximityGuard(entry.config, 'text', 'gs') ?? 'boolean kwOk = true;';
  const keepLast = entry.config.keepLast ?? 4;
  const maskPrefix = painlessSingleQuoted(entry.config.maskToken ?? '****');
  const checksumPart = isChecksum(entry.detector)
    ? checksumBody(entry.detector.detection.validation.type)
    : 'boolean ok = true;';
  const reportOnAny =
    flagReport?.withFlags === true
      ? [
          `  out += text.substring(last);`,
          `  ${painlessFieldAssignment(field)} = out;`,
          mergeSensitiveCategoryReport(entry.detector.id, flagReport.flagNamespace),
        ]
      : [`  out += text.substring(last); ${painlessFieldAssignment(field)} = out;`];
  const source = [
    `def value = ${painlessFieldAccessor(field)};`,
    `if (!(value instanceof String)) { return; }`,
    `String text = (String) value;`,
    `String out = ''; int last = 0; boolean any = false;`,
    scanLenDecl('text'),
    ...perCandidateLoopOpen(kind, regex, 'text', 'last', '__scanLen'),
    `    ${checksumPart}`,
    `    ${keywordGuard.split('\n').join('\n    ')}`,
    `    out += text.substring(last, gs);`,
    `    String repl;`,
    `    if (cand.length() <= ${keepLast}) { repl = cand; } else { repl = '${maskPrefix}' + cand.substring(cand.length() - ${keepLast}); }`,
    `    if (ok && kwOk) { out += repl; any = true; } else { out += text.substring(gs, ge); }`,
    ...perCandidateLoopClose(kind, 'last'),
    `if (any) {`,
    ...reportOnAny,
    `}`,
    ...truncationFlagLine('text', flagReport),
  ].join('\n');
  return {
    script: {
      lang: 'painless',
      description: `Partially redact ${entry.detector.displayName} (keep last ${keepLast})`,
      source,
    },
  } as IngestProcessorContainer;
};

const hashScript = (
  entry: CategoryCompileEntry,
  field: string,
  flagReport?: FlagReportOptions
): IngestProcessorContainer => {
  const scriptDetector = detectorForScriptRegex(entry.detector, entry.config);
  const regex =
    entry.detector.id === IPV6_PER_CANDIDATE_SCAN_ID ||
    entry.detector.id === IPV4_PER_CANDIDATE_SCAN_ID
      ? ''
      : hashCandidateRegex(scriptDetector);
  const kind = candidateLoopKind(entry.detector.id, regex);
  const keywordGuard =
    painlessKeywordProximityGuard(entry.config, 'text', 'gs') ?? 'boolean kwOk = true;';
  const checksumPart = isChecksum(entry.detector)
    ? checksumBody(entry.detector.detection.validation.type)
    : 'boolean ok = true;';
  const reportOnAny =
    flagReport?.withFlags === true
      ? [
          `  out.append(text, last, text.length());`,
          `  ${painlessFieldAssignment(field)} = out.toString();`,
          mergeSensitiveCategoryReport(entry.detector.id, flagReport.flagNamespace),
        ]
      : [
          `  out.append(text, last, text.length());`,
          `  ${painlessFieldAssignment(field)} = out.toString();`,
        ];
  const source = [
    `def value = ${painlessFieldAccessor(field)};`,
    `if (!(value instanceof String)) { return; }`,
    `String text = (String) value;`,
    `StringBuilder out = new StringBuilder();`,
    `int last = 0; boolean any = false;`,
    scanLenDecl('text'),
    ...perCandidateLoopOpen(kind, regex, 'text', 'last', '__scanLen'),
    `    ${checksumPart}`,
    `    ${keywordGuard.split('\n').join('\n    ')}`,
    `    out.append(text, last, gs);`,
    `    ${painlessAssignFingerprintFromRange('text', 'gs', 'ge', 'repl')
      .split('\n')
      .join('\n    ')}`,
    `    if (ok && kwOk) { out.append(repl); any = true; } else { out.append(text, gs, ge); }`,
    ...perCandidateLoopClose(kind, 'last'),
    `if (any) {`,
    ...reportOnAny,
    `}`,
    ...truncationFlagLine('text', flagReport),
  ].join('\n');
  return {
    script: {
      lang: 'painless',
      description: `Hash ${entry.detector.displayName} matches (FNV-1a 64-bit fingerprint)`,
      source,
    },
  } as IngestProcessorContainer;
};

/** (e.g. `<EMAIL>`) to per-category custom tokens. The
 * native combined `redact` processor always emits `<CAPTURE_NAME>`, so custom tokens for structural
 * (non-checksum) detectors are applied here. Runs AFTER the telemetry flag script (which detects
 * structural redactions by their default token) and uses a literal `String.replace` (no regex), so
 * it is exempt from the Painless regex char-scan limit.
 */
const tokenRewriteScript = (
  rewrites: Array<{ from: string; to: string }>,
  field: string
): IngestProcessorContainer => {
  const lines = [
    `def value = ${painlessFieldAccessor(field)};`,
    `if (!(value instanceof String)) { return; }`,
    `String f = (String) value;`,
  ];
  for (const { from, to } of rewrites) {
    lines.push(`f = f.replace('${painlessSingleQuoted(from)}', '${painlessSingleQuoted(to)}');`);
  }
  lines.push(`${painlessFieldAssignment(field)} = f;`);
  return {
    script: {
      lang: 'painless',
      description: 'Apply custom mask tokens for structural sensitive-data detectors',
      source: lines.join('\n'),
    },
  } as IngestProcessorContainer;
};

/**
 * Compile configured category instances into ingest processors (per-category action, mask token,
 * keyword overrides). Use {@link compileCombinedRedact} for detector-only (all redact) paths.
 */
export const compileFromCategories = (
  categories: SensitiveDataCategory[],
  {
    field = 'message',
    withFlags = false,
    flagNamespace = DEFAULT_FLAG_NAMESPACE,
    structuralOnly = false,
  }: CompileOptions = {}
): { processors: IngestProcessorContainer[]; warnings: string[] } => {
  const { entries, warnings } = resolveCategoryEntries(categories);
  if (structuralOnly) {
    // tag entries mean "detect only, no redaction" — structural_only does not change that contract.
    const tagIds = entries.filter((e) => e.config.action === 'tag').map((e) => e.detector.id);
    if (tagIds.length) {
      warnings.push(
        `Categories [${tagIds.join(
          ', '
        )}] with action "tag" produce no redaction and are skipped in structural_only mode.`
      );
    }
    // partial entries require a per-candidate Painless script that structural_only explicitly avoids;
    // promote them to full structural redact so the data is still protected.
    const partialIds = entries
      .filter((e) => e.config.action === 'partial' || e.config.action === 'hash')
      .map((e) => e.detector.id);
    if (partialIds.length) {
      warnings.push(
        `Categories [${partialIds.join(
          ', '
        )}] hash/partial action promoted to full redact in structural_only mode (per-candidate scripts unavailable).`
      );
    }
    const redactableDetectors = entries
      .filter((e) => e.config.action !== 'tag')
      .map((e) => e.detector);
    const { processors } = compileCombinedRedact(redactableDetectors, {
      field,
      withFlags,
      flagNamespace,
      structuralOnly: true,
    });
    return { processors, warnings };
  }

  const redactEntries = entries.filter((e) => e.config.action === 'redact');
  const partialEntries = entries.filter((e) => e.config.action === 'partial');
  const hashEntries = entries.filter((e) => e.config.action === 'hash');

  const processors: IngestProcessorContainer[] = [];

  const redactDetectors = redactEntries.map((e) => e.detector);
  const nonChecksum = redactDetectors.filter((d) => !isChecksum(d));
  const checksumRedact = redactEntries.filter((e) => isChecksum(e.detector));

  if (nonChecksum.length) {
    processors.push(
      combinedRedactProcessor(
        nonChecksum,
        field,
        'Redact sensitive data (combined, structural detectors)'
      )
    );
  }
  const flagReport: FlagReportOptions | undefined = withFlags
    ? { withFlags: true, flagNamespace }
    : undefined;

  for (const entry of checksumRedact) {
    processors.push(
      confirmScript(
        entry.detector,
        field,
        tokenForCategory(entry.detector, entry.config),
        flagReport
      )
    );
  }

  for (const entry of partialEntries) {
    processors.push(partialRedactScript(entry, field, flagReport));
  }

  for (const entry of hashEntries) {
    processors.push(hashScript(entry, field, flagReport));
  }

  if (withFlags) {
    processors.push(flagScriptFromEntries(entries, field, flagNamespace));
  }

  // Structural (non-checksum) detectors redact via the native grok processor, which always emits the
  // default `<CAPTURE_NAME>` token. Apply any custom mask token last so telemetry (which keys off the
  // default token) still fires. Checksum and partial actions already write their own token inline.
  const tokenRewrites = redactEntries
    .filter((e) => !isChecksum(e.detector))
    .map((e) => ({ from: maskToken(e.detector), to: e.config.maskToken }))
    .filter((r): r is { from: string; to: string } => Boolean(r.to) && r.to !== r.from);
  if (tokenRewrites.length) {
    processors.push(tokenRewriteScript(tokenRewrites, field));
  }

  return { processors, warnings };
};

export const compileCombinedRedact = (
  detectors: Detector[],
  {
    field = 'message',
    withFlags = false,
    flagNamespace = DEFAULT_FLAG_NAMESPACE,
    structuralOnly = false,
  }: CompileOptions = {}
): { processors: IngestProcessorContainer[] } => {
  if (structuralOnly) {
    const processors: IngestProcessorContainer[] = [];
    if (detectors.length) {
      processors.push(
        combinedRedactProcessor(
          detectors,
          field,
          'Redact sensitive data (combined, structural-only)'
        )
      );
    }
    if (withFlags) processors.push(flagScript(detectors, field, flagNamespace));
    return { processors };
  }

  // Confirmed (default): one structural redact for non-checksum detectors, then a per-candidate
  // checksum confirmer for each checksum detector.
  const nonChecksum = detectors.filter((d) => !isChecksum(d));
  const checksum = detectors.filter(isChecksum);

  const processors: IngestProcessorContainer[] = [];
  if (nonChecksum.length) {
    processors.push(
      combinedRedactProcessor(
        nonChecksum,
        field,
        'Redact sensitive data (combined, structural detectors)'
      )
    );
  }
  const flagReport: FlagReportOptions | undefined = withFlags
    ? { withFlags: true, flagNamespace }
    : undefined;
  for (const det of checksum) {
    processors.push(confirmScript(det, field, undefined, flagReport));
  }
  if (withFlags) {
    processors.push(
      flagScriptFromEntries(
        detectors.map((detector) => ({ detector, config: { id: detector.id, action: 'redact' } })),
        field,
        flagNamespace
      )
    );
  }
  return { processors };
};
