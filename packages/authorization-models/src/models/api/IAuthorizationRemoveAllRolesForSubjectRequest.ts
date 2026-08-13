// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Request to remove all roles for a subject.
 */
export interface IAuthorizationRemoveAllRolesForSubjectRequest {
	/**
	 * The request path parameters.
	 */
	pathParams: {
		/**
		 * The subject to remove all roles from.
		 */
		subject: string;
	};
}
