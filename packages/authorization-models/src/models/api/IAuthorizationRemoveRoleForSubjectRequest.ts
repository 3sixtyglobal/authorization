// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Request to remove a role for a subject.
 */
export interface IAuthorizationRemoveRoleForSubjectRequest {
	/**
	 * The request path parameters.
	 */
	pathParams: {
		/**
		 * The subject to remove the role from.
		 */
		subject: string;

		/**
		 * The role to remove.
		 */
		role: string;
	};
}
