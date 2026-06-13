/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import useObservable from 'react-use/lib/useObservable';
import { useKibana } from '../../../../../../../../hooks/use_kibana';

export interface SensitiveDataLicenseState {
  isLoading: boolean;
  /** True when the license supports the native redact processor (Platinum or higher). */
  hasRequiredLicense: boolean;
}

export const useSensitiveDataLicense = (): SensitiveDataLicenseState => {
  const {
    dependencies: {
      start: { licensing },
    },
  } = useKibana();
  const license = useObservable(licensing.license$);

  return {
    isLoading: !license,
    hasRequiredLicense: Boolean(license?.hasAtLeast('platinum')),
  };
};
