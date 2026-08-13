// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Request to get roles for a subject.
 */
export interface IAuthorizationGetRolesForSubjectRequest {
	/**
	 * The request path parameters.
	 */
	pathParams: {
		/**
		 * The subject to get roles for.
		 */
		subject: string;
	};
}
