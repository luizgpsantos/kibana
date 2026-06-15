/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  ACTIVE_DETECTOR_IDS,
  CATALOG,
  DETECTORS,
  PAYMENT_CARD_NETWORK_IDS,
  createDefaultCategoryConfig,
  getActiveDetectors,
  getCategoryMaskToken,
  listCatalogCategories,
  listLibraryCategories,
  listRecommendedCategories,
  requiresKeywordProximity,
} from '.';
import { compileFromCategories, isChecksum } from '../compile';

describe('sensitive_data catalog (active set)', () => {
  it('vendors active and legacy detector modules', () => {
    expect(Object.keys(DETECTORS).sort()).toEqual([
      'amex',
      'credit-card',
      'date-of-birth',
      'diners',
      'discover',
      'email',
      'iban',
      'jcb',
      'maestro',
      'mastercard',
      'us-ssn',
      'visa',
    ]);
  });

  it('the active scope dial points at email, payment-card networks, iban, and us-ssn', () => {
    expect(ACTIVE_DETECTOR_IDS).toEqual(['email', ...PAYMENT_CARD_NETWORK_IDS, 'iban', 'us-ssn']);
    expect(getActiveDetectors()).toHaveLength(10);
    expect(getActiveDetectors().map((d) => d.id)).toEqual([
      'email',
      ...PAYMENT_CARD_NETWORK_IDS,
      'iban',
      'us-ssn',
    ]);
  });

  it('active detectors use structural validation (legacy credit-card retains luhn)', () => {
    expect(DETECTORS.email.detection.validation.type).toBe('none');
    expect(DETECTORS.visa.detection.validation.type).toBe('none');
    expect(DETECTORS.iban.detection.validation.type).toBe('none');
    expect(DETECTORS['us-ssn'].detection.validation.type).toBe('none');
    expect(DETECTORS['credit-card'].detection.validation.type).toBe('luhn');
    expect(isChecksum(DETECTORS.visa)).toBe(false);
    expect(isChecksum(DETECTORS['credit-card'])).toBe(true);
  });

  it('requires keyword proximity for payment cards, iban, and us-ssn', () => {
    for (const id of [...PAYMENT_CARD_NETWORK_IDS, 'iban', 'us-ssn']) {
      expect(requiresKeywordProximity(id)).toBe(true);
    }
    expect(requiresKeywordProximity('email')).toBe(false);
  });

  it('exposes catalog metadata', () => {
    expect(CATALOG.version).toBe('0.3.0');
    expect(CATALOG.defaultPosture).toBe('opt-out');
  });

  it('lists library categories for the flyout (active set only)', () => {
    const library = listLibraryCategories();
    expect(library).toHaveLength(10);
    expect(library.find((e) => e.id === 'date-of-birth')).toBeUndefined();
    expect(library.find((e) => e.id === 'visa')).toBeDefined();
  });

  it('lists ACTIVE categories for the proposal form', () => {
    expect(listCatalogCategories()).toHaveLength(10);
  });

  it('default category configs include recommended keywords for gated detectors', () => {
    const visa = createDefaultCategoryConfig('visa');
    expect(visa.useRecommendedKeywords).toBe(true);
    expect(visa.keywords).toEqual(expect.arrayContaining(['card', 'visa']));
    expect(visa.keywordProximity).toBe(30);
    expect(createDefaultCategoryConfig('email')).toEqual({ id: 'email', action: 'redact' });
  });
});

describe('sensitive_data catalog — proposal surface', () => {
  it('exposes mask tokens per active category', () => {
    expect(getCategoryMaskToken('email')).toBe('<EMAIL>');
    expect(getCategoryMaskToken('visa')).toBe('<VISA>');
  });

  it('derives Recommended from active affinity only', () => {
    const recommended = listRecommendedCategories(['email']);
    const ids = recommended.map((c) => c.id);
    expect(ids.every((id) => ACTIVE_DETECTOR_IDS.includes(id))).toBe(true);
  });

  it('listRecommendedCategories never returns an id without a working detector', () => {
    for (const foundIds of [[], ['email'], [...ACTIVE_DETECTOR_IDS]]) {
      for (const { id } of listRecommendedCategories(foundIds)) {
        expect(DETECTORS[id]).toBeDefined();
      }
    }
  });

  it('returns no recommendations when all active detectors are configured', () => {
    expect(listRecommendedCategories([...ACTIVE_DETECTOR_IDS])).toEqual([]);
  });

  it('compileFromCategories emits no checksum scripts for the active set', () => {
    const categories = ACTIVE_DETECTOR_IDS.map((id) => createDefaultCategoryConfig(id));
    const { processors, warnings } = compileFromCategories(categories, { field: 'message' });
    expect(warnings).toEqual([]);
    expect(
      processors.every((p) => !p || !('script' in p) || !p.script?.description?.includes('checksum'))
    ).toBe(true);
    expect(processors.some((p) => p && 'redact' in p)).toBe(true);
  });
});
