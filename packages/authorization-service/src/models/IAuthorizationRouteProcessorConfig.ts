// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Configuration for the authorization processor
 */
export interface IAuthorizationRouteProcessorConfig {
	/**
	 * Include the stack with errors.
	 */
	includeErrorStack?: boolean;

	/**
	 * The model identifier to use when checking route authorization.
	 * @default rest.
	 */
	authorizationModelId?: string;
}
