// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Request to get all authorization roles.
 */
export interface IAuthorizationGetAllRolesRequest {
	/**
	 * The optional query parameters.
	 */
	query?: {
		/**
		 * The cursor to request the next chunk of results.
		 */
		cursor?: string;

		/**
		 * Limit the number of roles to return.
		 */
		limit?: string;
	};
}
