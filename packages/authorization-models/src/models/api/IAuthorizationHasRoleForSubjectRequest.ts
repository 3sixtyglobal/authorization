// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Request to check if a subject has a role.
 */
export interface IAuthorizationHasRoleForSubjectRequest {
	/**
	 * The request path parameters.
	 */
	pathParams: {
		/**
		 * The subject to check.
		 */
		subject: string;

		/**
		 * The role to check.
		 */
		role: string;
	};
}
