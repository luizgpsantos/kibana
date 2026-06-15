/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { catalogIndexData } from './catalog_data';
import { amexDetector } from './detectors/amex_data';
import { creditCardDetector } from './detectors/credit_card_data';
import { dateOfBirthDetector } from './detectors/date_of_birth_data';
import { dinersDetector } from './detectors/diners_data';
import { discoverDetector } from './detectors/discover_data';
import { emailDetector } from './detectors/email_data';
import { ibanDetector } from './detectors/iban_data';
import { jcbDetector } from './detectors/jcb_data';
import { maestroDetector } from './detectors/maestro_data';
import { mastercardDetector } from './detectors/mastercard_data';
import { usSsnDetector } from './detectors/us_ssn_data';
import { visaDetector } from './detectors/visa_data';
import type { SensitiveDataCategory } from '../../../types/processors';
import { buildDefaultCategoryConfig, getCategoryKeywordCatalog } from './category_keyword_catalog';

export {
  buildDefaultCategoryConfig,
  getCategoryKeywordCatalog,
  getDefaultKeywordProximity,
  getRecommendedKeywords,
  requiresKeywordProximity,
  disableRecommendedKeywordsSync,
  omitKeywordOverrides,
  withRecommendedKeywords,
  withoutKeywordOverrides,
} from './category_keyword_catalog';
export type { CategoryKeywordCatalogEntry } from './category_keyword_catalog';
export {
  PAYMENT_CARD_NETWORK_IDS,
  PAYMENT_CARD_KEYWORD_PROXIMITY,
  SHARED_PAYMENT_CARD_KEYWORDS,
  paymentCardKeywords,
} from './payment_card_keywords';
export type { PaymentCardNetworkId } from './payment_card_keywords';
import { PAYMENT_CARD_NETWORK_IDS } from './payment_card_keywords';
import { maskToken } from '../mask';

/** Default configured instance when adding a category from the library. */
export const createDefaultCategoryConfig = (id: string): SensitiveDataCategory =>
  buildDefaultCategoryConfig(id);

export type ChecksumType = 'luhn' | 'mod97' | 'painless' | 'none';

export interface DetectorValidation {
  type: ChecksumType;
  appliesToField?: string;
  painless?: string;
}

export interface Detector {
  id: string;
  displayName: string;
  description?: string;
  categories: string[];
  detection: {
    grokPatterns: string[];
    grokPatternDefinitions?: Record<string, string>;
    validation: DetectorValidation;
  };
  recommendedAction?: string;
  defaultPrecisionGuards?: string[];
  anticipatoryAffinity?: string[];
}

export interface CatalogMetadata {
  name: string;
  version: string;
  defaultPosture: string;
  defaultAction: string;
}

export const CATALOG: CatalogMetadata = {
  name: catalogIndexData.name,
  version: catalogIndexData.version,
  defaultPosture: catalogIndexData.defaultPosture,
  defaultAction: catalogIndexData.defaultAction,
};

/** All detectors physically vendored into the package (includes legacy ids for migration). */
export const DETECTORS: Readonly<Record<string, Detector>> = {
  visa: visaDetector as Detector,
  mastercard: mastercardDetector as Detector,
  amex: amexDetector as Detector,
  discover: discoverDetector as Detector,
  diners: dinersDetector as Detector,
  jcb: jcbDetector as Detector,
  maestro: maestroDetector as Detector,
  email: emailDetector as Detector,
  iban: ibanDetector as Detector,
  'us-ssn': usSsnDetector as Detector,
  /** Legacy generic card id — migrated to payment-card network ids; retained for checksum compile tests. */
  'credit-card': creditCardDetector as Detector,
  /** Inactive — removed from the active set; retained for migration warnings only. */
  'date-of-birth': dateOfBirthDetector as Detector,
};

/**
 * Detectors offered in the product UI and library flyout.
 * Payment cards use per-network issuer-prefix patterns with required keyword proximity.
 */
export const ACTIVE_DETECTOR_IDS: readonly string[] = [
  'email',
  ...PAYMENT_CARD_NETWORK_IDS,
  'iban',
  'us-ssn',
];

export const getDetectorById = (id: string): Detector | undefined => DETECTORS[id];

export const getDetectorsByIds = (ids: readonly string[]): Detector[] =>
  ids.map((id) => {
    const detector = getDetectorById(id);
    if (!detector) {
      throw new Error(`Unknown detector id: "${id}"`);
    }
    return detector;
  });

export const getActiveDetectors = (): Detector[] => getDetectorsByIds(ACTIVE_DETECTOR_IDS);

export interface CatalogCategory {
  id: string;
  displayName: string;
  categories: string[];
  recommendedAction: string;
  precisionGuards: string[];
  maskToken: string;
  anticipatoryAffinity: string[];
  requiresKeywordProximity: boolean;
  recommendedKeywords: readonly string[];
  defaultKeywordProximity?: number;
}

export interface RecommendedCategory {
  id: string;
  displayName: string;
}

/** Library browser grouping (aligned with common SDS-style category filters). */
export type LibraryCategoryGroup =
  | 'pii'
  | 'payment_banking'
  | 'network_device'
  | 'secrets_credentials';

export interface LibraryCategoryEntry {
  id: string;
  displayName: string;
  description?: string;
  group: LibraryCategoryGroup;
  complianceTags: string[];
  maskToken: string;
  precisionGuards: string[];
  recommendedAction: string;
}

const libraryGroupForDetector = (
  detector: Detector | undefined,
  metaCategories: string[]
): LibraryCategoryGroup => {
  if (metaCategories.includes('PCI DSS') || metaCategories.includes('Financial')) {
    return 'payment_banking';
  }
  return 'pii';
};

/** Categories the library flyout offers — same active scope dial as {@link listCatalogCategories}. */
export const listLibraryCategories = (): LibraryCategoryEntry[] =>
  getActiveDetectors().map((detector) => {
    const meta = catalogIndexData.detectors.find((d) => d.id === detector.id);
    const metaCategories = meta ? [...meta.categories] : detector.categories;
    return {
      id: detector.id,
      displayName: detector.displayName,
      description: detector.description,
      group: libraryGroupForDetector(detector, metaCategories),
      complianceTags: metaCategories,
      maskToken: maskToken(detector),
      precisionGuards: detector.defaultPrecisionGuards ?? [],
      recommendedAction: detector.recommendedAction ?? CATALOG.defaultAction,
    };
  });

export const getCategoryMaskToken = (id: string): string | undefined => {
  const detector = DETECTORS[id];
  return detector ? maskToken(detector) : undefined;
};

/** Categories the UI offers — driven by the active scope dial, not every vendored detector. */
export const listCatalogCategories = (): CatalogCategory[] =>
  getActiveDetectors().map((d) => {
    const keywordCatalog = getCategoryKeywordCatalog(d.id);
    return {
      id: d.id,
      displayName: d.displayName,
      categories: d.categories,
      recommendedAction: d.recommendedAction ?? CATALOG.defaultAction,
      precisionGuards: d.defaultPrecisionGuards ?? [],
      maskToken: maskToken(d),
      anticipatoryAffinity: d.anticipatoryAffinity ?? [],
      requiresKeywordProximity: keywordCatalog?.requiresKeywordProximity ?? false,
      recommendedKeywords: keywordCatalog?.recommendedKeywords ?? [],
      defaultKeywordProximity: keywordCatalog?.defaultKeywordProximity,
    };
  });

/**
 * Related active categories not yet configured (from anticipatoryAffinity on configured detectors).
 */
export const listRecommendedCategories = (foundIds: string[]): RecommendedCategory[] => {
  const found = new Set(foundIds);
  const labelById = new Map(listCatalogCategories().map((c) => [c.id, c.displayName] as const));
  const activeSet = new Set<string>(ACTIVE_DETECTOR_IDS);

  const recommendedIds = new Set<string>();
  for (const detector of getActiveDetectors()) {
    for (const affineId of detector.anticipatoryAffinity ?? []) {
      if (!found.has(affineId) && activeSet.has(affineId) && DETECTORS[affineId]) {
        recommendedIds.add(affineId);
      }
    }
  }

  return [...recommendedIds].map((id) => ({
    id,
    displayName: labelById.get(id) ?? id,
  }));
};
