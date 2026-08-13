// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Response for getting all authorization roles.
 */
export interface IAuthorizationGetAllRolesResponse {
	/**
	 * The response body.
	 */
	body: {
		/**
		 * The list of role names.
		 */
		roles: string[];

		/**
		 * An optional cursor, when defined can be used to retrieve the next chunk of results.
		 */
		cursor?: string;
	};
}
