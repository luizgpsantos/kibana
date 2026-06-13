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
  createDefaultCategoryConfig,
  getActiveDetectors,
  getDetectorsByIds,
  getCategoryMaskToken,
  listCatalogCategories,
  listLibraryCategories,
  listRecommendedCategories,
} from '.';
import { compileFromCategories, isChecksum } from '../compile';

describe('sensitive_data catalog (Plan 6 — confirmed active set)', () => {
  it('vendors the curated detector modules', () => {
    expect(Object.keys(DETECTORS).sort()).toEqual([
      'credit-card',
      'date-of-birth',
      'email',
      'iban',
      'us-ssn',
    ]);
  });

  it('the active scope dial points at the confirmed set', () => {
    expect(ACTIVE_DETECTOR_IDS).toEqual([
      'date-of-birth',
      'email',
      'credit-card',
      'iban',
      'us-ssn',
    ]);
    expect(getActiveDetectors().map((d) => d.id)).toEqual([
      'date-of-birth',
      'email',
      'credit-card',
      'iban',
      'us-ssn',
    ]);
  });

  it('classifies validation types: structural vs per-candidate checksum', () => {
    expect(DETECTORS['date-of-birth'].detection.validation.type).toBe('none');
    expect(DETECTORS.email.detection.validation.type).toBe('none');
    expect(DETECTORS['us-ssn'].detection.validation.type).toBe('none');
    expect(DETECTORS['credit-card'].detection.validation.type).toBe('luhn');
    expect(DETECTORS.iban.detection.validation.type).toBe('mod97');
    expect(isChecksum(DETECTORS['credit-card'])).toBe(true);
    expect(isChecksum(DETECTORS.iban)).toBe(true);
    expect(isChecksum(DETECTORS['us-ssn'])).toBe(false);
  });

  it('keeps end-user precision guards in plain language (no checksum jargon)', () => {
    expect(DETECTORS['credit-card'].defaultPrecisionGuards).toEqual(['Redact credit card numbers']);
    expect(DETECTORS.iban.defaultPrecisionGuards).toEqual(['Redact IBANs (bank account numbers)']);
    expect(DETECTORS['us-ssn'].defaultPrecisionGuards).toEqual([
      'Only redact Social Security numbers labeled nearby',
    ]);
  });

  it('exposes catalog metadata (version + opt-out posture)', () => {
    expect(CATALOG.version).toBe('0.2.0');
    expect(CATALOG.defaultPosture).toBe('opt-out');
    expect(CATALOG.defaultAction).toBe('remove');
  });

  it('resolves detectors by id, preserving requested order', () => {
    const detectors = getDetectorsByIds(['email', 'credit-card', 'date-of-birth']);
    expect(detectors.map((d) => d.id)).toEqual(['email', 'credit-card', 'date-of-birth']);
  });

  it('throws on an unknown detector id', () => {
    expect(() => getDetectorsByIds(['does-not-exist'])).toThrow(/unknown detector/i);
  });

  it('lists library categories for the flyout (active set only)', () => {
    const library = listLibraryCategories();
    expect(library).toHaveLength(5);
    expect(library.map((e) => e.id)).toEqual([
      'date-of-birth',
      'email',
      'credit-card',
      'iban',
      'us-ssn',
    ]);
    expect(library.find((e) => e.id === 'passport-national-id')).toBeUndefined();
  });

  it('lists ACTIVE categories for the proposal form', () => {
    const categories = listCatalogCategories();
    expect(categories).toHaveLength(5);
    expect(categories.map((c) => c.id)).toEqual([
      'date-of-birth',
      'email',
      'credit-card',
      'iban',
      'us-ssn',
    ]);
  });
});

describe('sensitive_data catalog — proposal surface', () => {
  it('exposes a mask token per active category', () => {
    expect(getCategoryMaskToken('date-of-birth')).toBe('<DOB>');
    expect(getCategoryMaskToken('email')).toBe('<EMAIL>');
    expect(getCategoryMaskToken('credit-card')).toBe('<CREDIT_CARD>');
  });

  it('returns undefined mask token for an unknown id (no throw)', () => {
    expect(getCategoryMaskToken('not-a-detector')).toBeUndefined();
  });

  it('exposes anticipatoryAffinity on active categories', () => {
    const [dob] = listCatalogCategories();
    expect(dob.id).toBe('date-of-birth');
    expect(dob.anticipatoryAffinity).toEqual(expect.arrayContaining(['us-ssn', 'email']));
  });

  it('derives Recommended from active affinity only, excluding already configured ids', () => {
    const recommended = listRecommendedCategories(['date-of-birth']);
    const ids = recommended.map((c) => c.id);
    expect(ids).not.toContain('date-of-birth');
    expect(ids).toEqual(expect.arrayContaining(['us-ssn', 'email']));
    expect(ids.every((id) => ACTIVE_DETECTOR_IDS.includes(id))).toBe(true);
  });

  it('listRecommendedCategories never returns an id without a working detector', () => {
    for (const foundIds of [
      [],
      ['date-of-birth'],
      [...ACTIVE_DETECTOR_IDS],
      ['email', 'credit-card'],
    ]) {
      for (const { id } of listRecommendedCategories(foundIds)) {
        expect(DETECTORS[id]).toBeDefined();
      }
    }
  });

  it('returns no recommendations when all active detectors are configured', () => {
    expect(listRecommendedCategories([...ACTIVE_DETECTOR_IDS])).toEqual([]);
  });

  it('compileFromCategories emits no warnings for all active detectors', () => {
    const categories = ACTIVE_DETECTOR_IDS.map((id) => createDefaultCategoryConfig(id));
    const { warnings } = compileFromCategories(categories, { field: 'message' });
    expect(warnings).toEqual([]);
  });
});
