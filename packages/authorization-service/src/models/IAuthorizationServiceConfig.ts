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
}
