// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Response for getting child roles for a role.
 */
export interface IAuthorizationGetChildRolesResponse {
	/**
	 * The response body.
	 */
	body: {
		/**
		 * The list of child roles.
		 */
		roles: string[];
	};
}
