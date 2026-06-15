/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/** Active network / device identifiers in the sensitive-data catalog. */
export const NETWORK_DEVICE_IDS = ['ipv4', 'ipv6', 'mac-address'] as const;

export type NetworkDeviceId = (typeof NETWORK_DEVICE_IDS)[number];
