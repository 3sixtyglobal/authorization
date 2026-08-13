// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Request to add a role for a subject.
 */
export interface IAuthorizationAddRoleForSubjectRequest {
	/**
	 * The request path parameters.
	 */
	pathParams: {
		/**
		 * The subject to add the role to.
		 */
		subject: string;
	};

	/**
	 * The request data.
	 */
	body: {
		/**
		 * The role to add.
		 */
		role: string;
	};
}
