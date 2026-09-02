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
	 * Maximum number of check results to hold in the cache
	 * @default 1000.
	 */
	checkCacheCapacity?: number;

	/**
	 * Time-to-idle in milliseconds for cached check results.
	 * @default 60000.
	 */
	checkCacheTtiMs?: number;

	/**
	 * The model identifier that is reserved for system-only use.
	 * @default system
	 */
	authorizationModelId?: string;

	/**
	 * The role that bypasses all escalation guards when held by the caller.
	 * @default global-admin
	 */
	escalatedPrivilegeRole?: string;
}
