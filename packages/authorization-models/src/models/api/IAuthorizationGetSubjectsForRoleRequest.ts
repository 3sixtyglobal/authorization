// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Request to get subjects for a role.
 */
export interface IAuthorizationGetSubjectsForRoleRequest {
	/**
	 * The request path parameters.
	 */
	pathParams: {
		/**
		 * The role to get subjects for.
		 */
		role: string;
	};
}
