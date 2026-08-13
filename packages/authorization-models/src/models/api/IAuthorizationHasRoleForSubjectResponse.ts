// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Response for checking if a subject has a role.
 */
export interface IAuthorizationHasRoleForSubjectResponse {
	/**
	 * The response body.
	 */
	body: {
		/**
		 * Whether the subject has the role.
		 */
		hasRole: boolean;
	};
}
