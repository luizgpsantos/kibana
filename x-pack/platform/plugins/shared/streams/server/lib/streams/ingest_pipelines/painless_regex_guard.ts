/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { ElasticsearchClient } from '@kbn/core/server';
import type { StreamlangDSL } from '@kbn/streamlang';
import {
  getDetectorById,
  isChecksum,
  isConditionBlock,
  normalizeSensitiveDataCategories,
} from '@kbn/streamlang';
import type { SensitiveDataCategory } from '@kbn/streamlang';

/**
 * The `sensitive_data` checksum confirmers (credit-card Luhn, IBAN mod-97) are compiled to a
 * Painless `script` processor that uses a regex literal (`/.../.matcher(...)`). That depends on the
 * cluster setting `script.painless.regex.enabled`, which can be set to `false` to fully disable
 * Painless regex. When it is disabled, those pipelines fail at ingest, so we block configuring them
 * up front with a clear message instead of letting the user hit a cryptic runtime failure.
 *
 * `limited` (the Elasticsearch default) still allows the simple, non-parameterized regex literals we
 * emit, so only an explicit `false` is treated as disabled.
 */

const collectSensitiveDataSteps = (
  steps: StreamlangDSL['steps']
): Array<{ categories?: SensitiveDataCategory[] | string[]; structural_only?: boolean }> => {
  const found: Array<{
    categories?: SensitiveDataCategory[] | string[];
    structural_only?: boolean;
  }> = [];
  for (const step of steps) {
    if (isConditionBlock(step)) {
      found.push(...collectSensitiveDataSteps(step.condition.steps));
      if (step.condition.else) {
        found.push(...collectSensitiveDataSteps(step.condition.else));
      }
      continue;
    }
    if ('action' in step && step.action === 'sensitive_data') {
      found.push(
        step as { categories?: SensitiveDataCategory[] | string[]; structural_only?: boolean }
      );
    }
  }
  return found;
};

/**
 * Whether the processing pipeline includes a `sensitive_data` step that relies on a per-candidate
 * checksum confirmer (i.e. a checksum detector that is not running in `structural_only` mode).
 */
const categoryUsesPainlessRegex = (category: SensitiveDataCategory): boolean => {
  if (category.action === 'partial' || category.action === 'tag' || category.action === 'hash') {
    return true;
  }
  const detector = getDetectorById(category.id);
  if (!detector) {
    return false;
  }
  return isChecksum(detector);
};

export const processingUsesChecksumRedaction = (processing: StreamlangDSL): boolean =>
  collectSensitiveDataSteps(processing.steps).some((step) => {
    if (step.structural_only === true) {
      return false;
    }
    const categories = normalizeSensitiveDataCategories(step.categories ?? []);
    return categories.some(categoryUsesPainlessRegex);
  });

const PAINLESS_REGEX_SETTING = 'script.painless.regex.enabled';

/** Reads the effective `script.painless.regex.enabled` cluster setting; `false` means disabled. */
export const isPainlessRegexDisabled = async (esClient: ElasticsearchClient): Promise<boolean> => {
  const settings = await esClient.cluster.getSettings({
    include_defaults: true,
    flat_settings: true,
  });
  const read = (source?: Record<string, unknown>): unknown => source?.[PAINLESS_REGEX_SETTING];
  const value = read(settings.transient) ?? read(settings.persistent) ?? read(settings.defaults);
  return value === 'false';
};

export const PAINLESS_REGEX_DISABLED_MESSAGE =
  'This processor configuration requires Painless regular expressions, which are disabled on this cluster (script.painless.regex.enabled is set to "false"). Hash, partial-redact, and tag actions emit Painless regex scripts. Enable the setting, switch to structural_only mode, or use only full-redact (action: "redact") to continue without regex scripts.';

/**
 * Returns an error message when the processing needs Painless regex but the cluster has it disabled,
 * or `undefined` when the configuration is safe to run.
 */
export const checkSensitiveDataPainlessRegex = async (
  processing: StreamlangDSL,
  esClient: ElasticsearchClient
): Promise<string | undefined> => {
  if (!processingUsesChecksumRedaction(processing)) {
    return undefined;
  }
  return (await isPainlessRegexDisabled(esClient)) ? PAINLESS_REGEX_DISABLED_MESSAGE : undefined;
};
