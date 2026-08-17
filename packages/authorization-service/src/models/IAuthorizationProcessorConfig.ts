// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Configuration for the authorization processor
 */
export interface IAuthorizationProcessorConfig {
	/**
	 * Include the stack with errors.
	 */
	includeErrorStack?: boolean;

	/**
	 * The role to use when no roles are present in the context IDs.
	 */
	defaultRole?: string;
}
