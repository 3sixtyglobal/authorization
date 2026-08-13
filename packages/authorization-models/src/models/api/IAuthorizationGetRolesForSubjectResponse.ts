// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Response for getting roles for a subject.
 */
export interface IAuthorizationGetRolesForSubjectResponse {
	/**
	 * The response body.
	 */
	body: {
		/**
		 * The list of roles for the subject.
		 */
		roles: string[];
	};
}
