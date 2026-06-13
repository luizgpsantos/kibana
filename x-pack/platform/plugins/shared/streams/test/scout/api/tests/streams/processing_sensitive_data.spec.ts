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
 * Exercises the real `sensitive_data` ingest pipeline against Elasticsearch (Painless Luhn/mod-97,
 * grok redact, and the telemetry flag script) — the unit tests only assert the compiled string
 * shapes, so this guards the runtime semantics that the hand-written Painless can only prove in ES.
 *
 * `logs.otel` is an OTel stream, so the telemetry flags land under `attributes.sensitive_data.*`.
 */
apiTest.describe(
  'Stream data processing - sensitive_data redaction',
  { tag: [...tags.stateful.classic, ...tags.serverless.observability.complete] },
  () => {
    const testStream = 'logs.otel';
    const allCategories = ['date-of-birth', 'email', 'credit-card', 'iban', 'us-ssn'];

    apiTest(
      'masks Luhn-valid cards but leaves an invalid card untouched, and sets OTel telemetry flags',
      async ({ apiClient, samlAuth }) => {
        const { cookieHeader } = await samlAuth.asStreamsAdmin();

        const { statusCode, body } = await apiClient.post(
          `internal/streams/${testStream}/processing/_simulate`,
          {
            headers: { ...COMMON_API_HEADERS, ...cookieHeader },
            body: {
              processing: {
                steps: [{ action: 'sensitive_data', from: 'body.text', categories: allCategories }],
              },
              documents: [
                {
                  'body.text': 'Payment received on card 4111 1111 1111 1111 thanks',
                  '@timestamp': new Date().toISOString(),
                },
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
        const [validDoc, invalidDoc] = body.documents;

        // Luhn-valid card is masked and the telemetry flags are recorded under attributes.*
        expect(validDoc.value['body.text']).not.toContain('4111 1111 1111 1111');
        expect(validDoc.value['body.text']).toContain('<CREDIT_CARD>');
        expect(validDoc.value['attributes.sensitive_data.detected']).toBe(true);
        expect(validDoc.value['attributes.sensitive_data.categories']).toContain('credit-card');

        // Luhn-invalid card is left intact and no flags are set.
        expect(invalidDoc.value['body.text']).toContain('4111 1111 1111 1112');
        expect(invalidDoc.value['attributes.sensitive_data.detected']).toBeUndefined();
      }
    );

    apiTest(
      'does not mask uniform-digit card numbers that pass Luhn but lack distinct digits',
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
                  'body.text': 'card 0000 0000 0000 0000 declined',
                  '@timestamp': new Date().toISOString(),
                },
                {
                  'body.text': 'card 1111 1111 1111 1111 declined',
                  '@timestamp': new Date().toISOString(),
                },
              ],
            },
            responseType: 'json',
          }
        );

        expect(statusCode).toBe(200);
        const [zerosDoc, onesDoc] = body.documents;

        expect(zerosDoc.value['body.text']).toContain('0000 0000 0000 0000');
        expect(zerosDoc.value['body.text']).not.toContain('<CREDIT_CARD>');
        expect(zerosDoc.value['attributes.sensitive_data.detected']).toBeUndefined();

        expect(onesDoc.value['body.text']).toContain('1111 1111 1111 1111');
        expect(onesDoc.value['body.text']).not.toContain('<CREDIT_CARD>');
        expect(onesDoc.value['attributes.sensitive_data.detected']).toBeUndefined();
      }
    );

    apiTest(
      'masks a mod-97-valid IBAN but leaves an invalid IBAN untouched',
      async ({ apiClient, samlAuth }) => {
        const { cookieHeader } = await samlAuth.asStreamsAdmin();

        const { statusCode, body } = await apiClient.post(
          `internal/streams/${testStream}/processing/_simulate`,
          {
            headers: { ...COMMON_API_HEADERS, ...cookieHeader },
            body: {
              processing: {
                steps: [{ action: 'sensitive_data', from: 'body.text', categories: allCategories }],
              },
              documents: [
                {
                  'body.text': 'iban DE89370400440532013000 on file',
                  '@timestamp': new Date().toISOString(),
                },
                {
                  'body.text': 'ticket GB00 WEST 0000 0000 0000 00 is invalid',
                  '@timestamp': new Date().toISOString(),
                },
              ],
            },
            responseType: 'json',
          }
        );

        expect(statusCode).toBe(200);
        const [validDoc, invalidDoc] = body.documents;

        expect(validDoc.value['body.text']).not.toContain('DE89370400440532013000');
        expect(validDoc.value['body.text']).toContain('<IBAN>');
        expect(validDoc.value['attributes.sensitive_data.categories']).toContain('iban');

        expect(invalidDoc.value['body.text']).toContain('GB00 WEST 0000 0000 0000 00');
        expect(invalidDoc.value['attributes.sensitive_data.detected']).toBeUndefined();
      }
    );

    apiTest(
      'masks structural detectors (email, date of birth)',
      async ({ apiClient, samlAuth }) => {
        const { cookieHeader } = await samlAuth.asStreamsAdmin();

        const { statusCode, body } = await apiClient.post(
          `internal/streams/${testStream}/processing/_simulate`,
          {
            headers: { ...COMMON_API_HEADERS, ...cookieHeader },
            body: {
              processing: {
                steps: [{ action: 'sensitive_data', from: 'body.text', categories: allCategories }],
              },
              documents: [
                {
                  'body.text': 'Contact the user at john.doe@example.com for follow-up',
                  '@timestamp': new Date().toISOString(),
                },
                {
                  'body.text': 'Patient DOB: 1985-07-23 recorded',
                  '@timestamp': new Date().toISOString(),
                },
              ],
            },
            responseType: 'json',
          }
        );

        expect(statusCode).toBe(200);
        const [emailDoc, dobDoc] = body.documents;

        expect(emailDoc.value['body.text']).not.toContain('john.doe@example.com');
        expect(emailDoc.value['attributes.sensitive_data.categories']).toContain('email');

        expect(dobDoc.value['body.text']).not.toContain('1985-07-23');
        expect(dobDoc.value['attributes.sensitive_data.categories']).toContain('date-of-birth');
      }
    );

    apiTest(
      'tags date of birth in Painless without exceeding the regex scan budget (Painless limit-factor)',
      async ({ apiClient, samlAuth }) => {
        const { cookieHeader } = await samlAuth.asStreamsAdmin();

        // `tag` runs the keyword+date regex inside a Painless script (the flag script), which is
        // capped by `script.painless.regex.limit-factor`. A short line with no DOB keyword is the
        // worst case (small budget, full keyword scan); it must not blow the budget or 500.
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
                    categories: [{ id: 'date-of-birth', action: 'tag' }],
                  },
                ],
              },
              documents: [
                {
                  'body.text': 'refund issued for Noah Rossi — Tax ID: 752-95-0738; email <EMAIL>',
                  '@timestamp': new Date().toISOString(),
                },
                {
                  'body.text':
                    'Patient intake notes: DOB 1985-07-23 confirmed by reception desk today',
                  '@timestamp': new Date().toISOString(),
                },
              ],
            },
            responseType: 'json',
          }
        );

        expect(statusCode).toBe(200);
        const [noDobDoc, dobDoc] = body.documents;

        // No DOB keyword: nothing fired, line untouched (the previous regex threw here).
        expect(noDobDoc.value['body.text']).toContain('752-95-0738');
        expect(noDobDoc.value['attributes.sensitive_data.detected']).toBeUndefined();

        // tag-only: the date stays in place but the category is recorded.
        expect(dobDoc.value['body.text']).toContain('1985-07-23');
        expect(dobDoc.value['attributes.sensitive_data.detected']).toBe(true);
        expect(dobDoc.value['attributes.sensitive_data.categories']).toContain('date-of-birth');
      }
    );

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
                    categories: ['email'],
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

    const assertCategories = (doc: { value: Record<string, unknown> }, expected: string[]) => {
      expect(doc.value['attributes.sensitive_data.detected']).toBe(true);
      expect(doc.value['attributes.sensitive_data.categories']).toStrictEqual(
        expect.arrayContaining(expected)
      );
      expect(doc.value['attributes.sensitive_data.categories']).toHaveLength(expected.length);
    };

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
                      { id: 'credit-card', action: 'redact', maskToken: sharedToken },
                      { id: 'iban', action: 'redact', maskToken: sharedToken },
                      { id: 'date-of-birth', action: 'redact', maskToken: sharedToken },
                      { id: 'us-ssn', action: 'redact', maskToken: sharedToken },
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
        assertCategories(doc, ['credit-card']);
      }
    );

    apiTest(
      'applies a custom mask token to a structural detector (email)',
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
                    categories: [{ id: 'email', action: 'redact', maskToken: '[redacted-email]' }],
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
        const [doc] = body.documents;
        // The custom token replaces the email, and the default <EMAIL> token never leaks through.
        expect(doc.value['body.text']).not.toContain('john.doe@example.com');
        expect(doc.value['body.text']).toContain('[redacted-email]');
        expect(doc.value['body.text']).not.toContain('<EMAIL>');
        // Telemetry still records the category despite the custom token.
        expect(doc.value['attributes.sensitive_data.detected']).toBe(true);
        expect(doc.value['attributes.sensitive_data.categories']).toContain('email');
      }
    );

    apiTest(
      'telemetry records only email when email is the sole configured category',
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
        assertCategories(body.documents[0], ['email']);
      }
    );

    apiTest(
      'telemetry records partial redaction without unrelated category ids',
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
                    categories: [{ id: 'credit-card', action: 'partial', keepLast: 4 }],
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
        expect(categories).toStrictEqual(['credit-card']);
        expect(categories).not.toContain('email');
        expect(categories).not.toContain('iban');
      }
    );

    apiTest(
      'telemetry lists exactly the mixed categories present in the document',
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
                    categories: [
                      { id: 'email', action: 'redact' },
                      { id: 'credit-card', action: 'redact' },
                      { id: 'iban', action: 'redact' },
                    ],
                  },
                ],
              },
              documents: [
                {
                  'body.text':
                    'Contact john.doe@example.com; card 4111 1111 1111 1111; iban DE89370400440532013000',
                  '@timestamp': new Date().toISOString(),
                },
              ],
            },
            responseType: 'json',
          }
        );

        expect(statusCode).toBe(200);
        assertCategories(body.documents[0], ['credit-card', 'email', 'iban']);
      }
    );

    apiTest(
      'honors a where condition for a checksum-only selection (Issue 2)',
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

        // The where condition must reach the confirmer script even with no structural redact.
        expect(inScope.value['body.text']).toContain('<CREDIT_CARD>');
        expect(outOfScope.value['body.text']).toContain('4111 1111 1111 1111');
      }
    );
  }
);
