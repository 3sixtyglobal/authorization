// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Response for getting subjects for a role.
 */
export interface IAuthorizationGetSubjectsForRoleResponse {
	/**
	 * The response body.
	 */
	body: {
		/**
		 * The list of subjects assigned to the role.
		 */
		subjects: string[];
	};
}
