// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Response for checking an authorization policy for any of a list of subjects.
 */
export interface IAuthorizationCheckAnyResponse {
	/**
	 * The response body.
	 */
	body: {
		/**
		 * Whether at least one subject is allowed to perform the action on the object.
		 */
		allowed: boolean;
	};
}
