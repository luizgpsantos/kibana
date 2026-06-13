/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import { EuiCallOut, EuiSpacer } from '@elastic/eui';
import { i18n } from '@kbn/i18n';

export const SensitiveDataLicenseCallout = () => (
  <>
    <EuiCallOut
      color="warning"
      iconType="warning"
      title={i18n.translate('xpack.streams.sensitiveData.license.title', {
        defaultMessage: 'Sensitive data redaction requires a Platinum or Enterprise license',
      })}
    >
      {i18n.translate('xpack.streams.sensitiveData.license.body', {
        defaultMessage:
          'Redaction uses the Elasticsearch redact processor, which is not available on your current license. The step can be configured but will not redact until you upgrade.',
      })}
    </EuiCallOut>
    <EuiSpacer size="m" />
  </>
);
