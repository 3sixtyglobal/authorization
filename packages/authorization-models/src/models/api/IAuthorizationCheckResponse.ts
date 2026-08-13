// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Response for checking an authorization policy.
 */
export interface IAuthorizationCheckResponse {
	/**
	 * The response body.
	 */
	body: {
		/**
		 * Whether the subject is allowed to perform the action on the object.
		 */
		allowed: boolean;
	};
}
