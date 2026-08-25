// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Request to check whether a list of roles exist in the system.
 */
export interface IAuthorizationHasRolesRequest {
	/**
	 * The request data.
	 */
	body: {
		/**
		 * The role names to check.
		 */
		roles: string[];
	};
}
