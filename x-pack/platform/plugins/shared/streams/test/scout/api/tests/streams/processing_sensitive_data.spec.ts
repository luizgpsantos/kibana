/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { expect } from '@kbn/scout/api';
import { tags } from '@kbn/scout';
import { streamsApiTest as apiTest } from '../../fixtures';
import { COMMON_API_HEADERS } from '../../fixtures/constants';

/**
 * Exercises the real `sensitive_data` ingest pipeline against Elasticsearch — the unit tests
 * only assert compiled processor shapes, so this guards runtime semantics in ES.
 *
 * `logs.otel` is an OTel stream, so the telemetry flags land under `attributes.sensitive_data.*`.
 */
apiTest.describe(
  'Stream data processing - sensitive_data redaction',
  { tag: [...tags.stateful.classic, ...tags.serverless.observability.complete] },
  () => {
    const testStream = 'logs.otel';

    const visaCategory = {
      id: 'visa',
      action: 'redact' as const,
      useRecommendedKeywords: true,
      keywords: ['card', 'visa', 'credit', 'pan'],
      keywordProximity: 30,
    };

    const ibanCategory = {
      id: 'iban',
      action: 'redact' as const,
      useRecommendedKeywords: true,
      keywords: ['iban', 'bank account', 'account number'],
      keywordProximity: 30,
    };

    apiTest(
      'masks Visa numbers when a payment-card keyword is nearby and sets OTel telemetry flags',
      async ({ apiClient, samlAuth }) => {
        const { cookieHeader } = await samlAuth.asStreamsAdmin();

        const { statusCode, body } = await apiClient.post(
          `internal/streams/${testStream}/processing/_simulate`,
          {
            headers: { ...COMMON_API_HEADERS, ...cookieHeader },
            body: {
              processing: {
                steps: [
                  {
                    action: 'sensitive_data',
                    from: 'body.text',
                    categories: [visaCategory, { id: 'email', action: 'redact' }],
                  },
                ],
              },
              documents: [
                {
                  'body.text': 'Payment received on card 4111 1111 1111 1111 thanks',
                  '@timestamp': new Date().toISOString(),
                },
                {
                  'body.text': '4111 1111 1111 1111 with no keyword nearby',
                  '@timestamp': new Date().toISOString(),
                },
              ],
            },
            responseType: 'json',
          }
        );

        expect(statusCode).toBe(200);
        const [withKeyword, withoutKeyword] = body.documents;

        expect(withKeyword.value['body.text']).not.toContain('4111 1111 1111 1111');
        expect(withKeyword.value['body.text']).toContain('<VISA>');
        expect(withKeyword.value['attributes.sensitive_data.detected']).toBe(true);
        expect(withKeyword.value['attributes.sensitive_data.categories']).toContain('visa');

        expect(withoutKeyword.value['body.text']).toContain('4111 1111 1111 1111');
        expect(withoutKeyword.value['attributes.sensitive_data.detected']).toBeUndefined();
      }
    );

    apiTest(
      'masks a Luhn-invalid Visa-shaped number when a payment-card keyword is present',
      async ({ apiClient, samlAuth }) => {
        const { cookieHeader } = await samlAuth.asStreamsAdmin();

        const { statusCode, body } = await apiClient.post(
          `internal/streams/${testStream}/processing/_simulate`,
          {
            headers: { ...COMMON_API_HEADERS, ...cookieHeader },
            body: {
              processing: {
                steps: [
                  {
                    action: 'sensitive_data',
                    from: 'body.text',
                    categories: [visaCategory],
                  },
                ],
              },
              documents: [
                {
                  'body.text': 'card 4111 1111 1111 1112 was declined',
                  '@timestamp': new Date().toISOString(),
                },
              ],
            },
            responseType: 'json',
          }
        );

        expect(statusCode).toBe(200);
        const [doc] = body.documents;
        expect(doc.value['body.text']).not.toContain('4111 1111 1111 1112');
        expect(doc.value['body.text']).toContain('<VISA>');
        expect(doc.value['attributes.sensitive_data.categories']).toContain('visa');
      }
    );

    apiTest('masks IBAN when a banking keyword is nearby', async ({ apiClient, samlAuth }) => {
      const { cookieHeader } = await samlAuth.asStreamsAdmin();

      const { statusCode, body } = await apiClient.post(
        `internal/streams/${testStream}/processing/_simulate`,
        {
          headers: { ...COMMON_API_HEADERS, ...cookieHeader },
          body: {
            processing: {
              steps: [
                {
                  action: 'sensitive_data',
                  from: 'body.text',
                  categories: [ibanCategory],
                },
              ],
            },
            documents: [
              {
                'body.text': 'customer iban DE89370400440532013000 on file',
                '@timestamp': new Date().toISOString(),
              },
              {
                'body.text': 'DE89370400440532013000 without keyword',
                '@timestamp': new Date().toISOString(),
              },
            ],
          },
          responseType: 'json',
        }
      );

      expect(statusCode).toBe(200);
      const [withKeyword, withoutKeyword] = body.documents;

      expect(withKeyword.value['body.text']).not.toContain('DE89370400440532013000');
      expect(withKeyword.value['body.text']).toContain('<IBAN>');
      expect(withKeyword.value['attributes.sensitive_data.categories']).toContain('iban');

      expect(withoutKeyword.value['body.text']).toContain('DE89370400440532013000');
      expect(withoutKeyword.value['attributes.sensitive_data.detected']).toBeUndefined();
    });

    apiTest('masks email addresses', async ({ apiClient, samlAuth }) => {
      const { cookieHeader } = await samlAuth.asStreamsAdmin();

      const { statusCode, body } = await apiClient.post(
        `internal/streams/${testStream}/processing/_simulate`,
        {
          headers: { ...COMMON_API_HEADERS, ...cookieHeader },
          body: {
            processing: {
              steps: [
                {
                  action: 'sensitive_data',
                  from: 'body.text',
                  categories: [{ id: 'email', action: 'redact' }],
                },
              ],
            },
            documents: [
              {
                'body.text': 'Contact the user at john.doe@example.com for follow-up',
                '@timestamp': new Date().toISOString(),
              },
            ],
          },
          responseType: 'json',
        }
      );

      expect(statusCode).toBe(200);
      const [emailDoc] = body.documents;
      expect(emailDoc.value['body.text']).not.toContain('john.doe@example.com');
      expect(emailDoc.value['attributes.sensitive_data.categories']).toContain('email');
    });

    apiTest(
      'reads and writes a hyphenated, dotted source field via the flexible accessor',
      async ({ apiClient, samlAuth }) => {
        const { cookieHeader } = await samlAuth.asStreamsAdmin();

        const { statusCode, body } = await apiClient.post(
          `internal/streams/${testStream}/processing/_simulate`,
          {
            headers: { ...COMMON_API_HEADERS, ...cookieHeader },
            body: {
              processing: {
                steps: [
                  {
                    action: 'sensitive_data',
                    from: 'attributes.custom-field',
                    categories: [{ id: 'email', action: 'redact' }],
                  },
                ],
              },
              documents: [
                {
                  'body.text': 'irrelevant',
                  'attributes.custom-field': 'reach me at jane@corp.example anytime',
                  '@timestamp': new Date().toISOString(),
                },
              ],
            },
            responseType: 'json',
          }
        );

        expect(statusCode).toBe(200);
        const [doc] = body.documents;
        expect(doc.value['attributes.custom-field']).not.toContain('jane@corp.example');
        expect(doc.value['attributes.sensitive_data.categories']).toContain('email');
      }
    );

    apiTest(
      'telemetry lists only the category that fired when categories share a custom mask token',
      async ({ apiClient, samlAuth }) => {
        const { cookieHeader } = await samlAuth.asStreamsAdmin();
        const sharedToken = 'REDACTED';

        const { statusCode, body } = await apiClient.post(
          `internal/streams/${testStream}/processing/_simulate`,
          {
            headers: { ...COMMON_API_HEADERS, ...cookieHeader },
            body: {
              processing: {
                steps: [
                  {
                    action: 'sensitive_data',
                    from: 'body.text',
                    categories: [
                      { id: 'email', action: 'redact', maskToken: sharedToken },
                      { ...visaCategory, maskToken: sharedToken },
                    ],
                  },
                ],
              },
              documents: [
                {
                  'body.text': 'Payment received on card 4111 1111 1111 1111 thanks',
                  '@timestamp': new Date().toISOString(),
                },
              ],
            },
            responseType: 'json',
          }
        );

        expect(statusCode).toBe(200);
        const [doc] = body.documents;
        expect(doc.value['body.text']).toContain(sharedToken);
        expect(doc.value['attributes.sensitive_data.detected']).toBe(true);
        expect(doc.value['attributes.sensitive_data.categories']).toStrictEqual(['visa']);
      }
    );

    apiTest(
      'telemetry records partial redaction for visa without unrelated category ids',
      async ({ apiClient, samlAuth }) => {
        const { cookieHeader } = await samlAuth.asStreamsAdmin();

        const { statusCode, body } = await apiClient.post(
          `internal/streams/${testStream}/processing/_simulate`,
          {
            headers: { ...COMMON_API_HEADERS, ...cookieHeader },
            body: {
              processing: {
                steps: [
                  {
                    action: 'sensitive_data',
                    from: 'body.text',
                    categories: [{ ...visaCategory, action: 'partial', keepLast: 4 }],
                  },
                ],
              },
              documents: [
                {
                  'body.text': 'Payment received on card 4111 1111 1111 1111 thanks',
                  '@timestamp': new Date().toISOString(),
                },
              ],
            },
            responseType: 'json',
          }
        );

        expect(statusCode).toBe(200);
        const categories = body.documents[0].value[
          'attributes.sensitive_data.categories'
        ] as string[];
        expect(categories).toStrictEqual(['visa']);
      }
    );

    apiTest(
      'honors a where condition on a keyword-gated visa selection',
      async ({ apiClient, samlAuth }) => {
        const { cookieHeader } = await samlAuth.asStreamsAdmin();

        const { statusCode, body } = await apiClient.post(
          `internal/streams/${testStream}/processing/_simulate`,
          {
            headers: { ...COMMON_API_HEADERS, ...cookieHeader },
            body: {
              processing: {
                steps: [
                  {
                    action: 'sensitive_data',
                    from: 'body.text',
                    categories: [visaCategory],
                    where: { field: 'attributes.scope', eq: 'payments' },
                  },
                ],
              },
              documents: [
                {
                  'body.text': 'card 4111 1111 1111 1111 charged',
                  'attributes.scope': 'payments',
                  '@timestamp': new Date().toISOString(),
                },
                {
                  'body.text': 'card 4111 1111 1111 1111 charged',
                  'attributes.scope': 'other',
                  '@timestamp': new Date().toISOString(),
                },
              ],
            },
            responseType: 'json',
          }
        );

        expect(statusCode).toBe(200);
        const [inScope, outOfScope] = body.documents;

        expect(inScope.value['body.text']).toContain('<VISA>');
        expect(outOfScope.value['body.text']).toContain('4111 1111 1111 1111');
      }
    );

    apiTest(
      'expands legacy credit-card category to payment-card networks at simulate time',
      async ({ apiClient, samlAuth }) => {
        const { cookieHeader } = await samlAuth.asStreamsAdmin();

        const { statusCode, body } = await apiClient.post(
          `internal/streams/${testStream}/processing/_simulate`,
          {
            headers: { ...COMMON_API_HEADERS, ...cookieHeader },
            body: {
              processing: {
                steps: [
                  {
                    action: 'sensitive_data',
                    from: 'body.text',
                    categories: ['credit-card'],
                  },
                ],
              },
              documents: [
                {
                  'body.text': 'card 4111 1111 1111 1111 charged',
                  '@timestamp': new Date().toISOString(),
                },
              ],
            },
            responseType: 'json',
          }
        );

        expect(statusCode).toBe(200);
        const [doc] = body.documents;
        expect(doc.value['body.text']).toContain('<VISA>');
        expect(doc.value['attributes.sensitive_data.categories']).toContain('visa');
      }
    );
  }
);
