/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { SensitiveDataCategory, SensitiveDataCategoryAction } from '../../types/processors';
import { DETECTORS, type Detector } from './catalog';
import { confirmCandidateRegex } from './confirm_candidate_regex';

/** Whether {@link confirmCandidateRegex} can build a value-capture matcher for this detector. */
export const detectorHasValueCapture = (detector: Detector): boolean => {
  try {
    confirmCandidateRegex(detector);
    return true;
  } catch {
    return false;
  }
};

export const detectorSupportsAction = (
  detector: Detector,
  action: SensitiveDataCategoryAction
): boolean => getSupportedActionsForCategory(detector.id).includes(action);

/** Actions the UI and compiler may use for a catalog category id. */
export const getSupportedActionsForCategory = (
  categoryId: string
): SensitiveDataCategoryAction[] => {
  const detector = DETECTORS[categoryId];
  if (!detector) {
    return ['redact'];
  }
  const supported: SensitiveDataCategoryAction[] = ['redact'];
  if (detectorHasValueCapture(detector)) {
    supported.push('partial', 'tag');
  }
  return supported;
};

/** Degrade unsupported persisted actions instead of throwing at compile time. */
export const normalizeCategoryActionForCompile = (
  config: SensitiveDataCategory,
  detector: Detector
): { config: SensitiveDataCategory; warning?: string } => {
  if ((config.action as string) === 'hash') {
    return {
      config: { ...config, action: 'redact' },
      warning: `Category "${config.id}": action "hash" is no longer supported; using full redact.`,
    };
  }
  if (detectorSupportsAction(detector, config.action)) {
    return { config };
  }
  return {
    config: { ...config, action: 'redact' },
    warning: `Category "${config.id}": action "${config.action}" is not supported for this detector; using full redact.`,
  };
};
