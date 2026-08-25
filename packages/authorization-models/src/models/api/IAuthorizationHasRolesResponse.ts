// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Response for checking whether a list of roles exist in the system.
 */
export interface IAuthorizationHasRolesResponse {
	/**
	 * The response body.
	 */
	body: {
		/**
		 * Whether each role exists, in the same order as the request.
		 */
		exists: boolean[];
	};
}
