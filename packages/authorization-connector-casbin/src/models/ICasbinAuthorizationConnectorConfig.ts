// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Configuration for the Casbin authorization connector.
 */
export interface ICasbinAuthorizationConnectorConfig {
	/**
	 * The base URL of the Casbin server (e.g. "http://localhost:48000").
	 */
	endpoint: string;

	/**
	 * The OAuth2 client ID for authenticating with the Casbin server API.
	 */
	clientId: string;

	/**
	 * The OAuth2 client secret for authenticating with the Casbin server API.
	 */
	clientSecret: string;

	/**
	 * The request timeout in milliseconds.
	 */
	timeoutMs?: number;
}
