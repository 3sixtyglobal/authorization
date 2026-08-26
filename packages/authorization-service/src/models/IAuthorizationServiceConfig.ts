// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Configuration for the Authorization Service.
 */
export interface IAuthorizationServiceConfig {
	/**
	 * The default connector namespace to use for authorization; defaults to the first registered connector.
	 */
	defaultNamespace?: string;

	/**
	 * The model identifier to use when migrating old authorization data.
	 * @default rest.
	 */
	migrationModelId?: string;

	/**
	 * Maximum number of check results to hold in the cache; defaults to 1000.
	 */
	checkCacheCapacity?: number;

	/**
	 * Time-to-idle in milliseconds for cached check results; defaults to 10000.
	 */
	checkCacheTtiMs?: number;
}
