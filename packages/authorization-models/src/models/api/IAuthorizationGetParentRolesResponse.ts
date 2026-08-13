// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Response for getting parent roles for a role.
 */
export interface IAuthorizationGetParentRolesResponse {
	/**
	 * The response body.
	 */
	body: {
		/**
		 * The list of parent roles.
		 */
		roles: string[];
	};
}
