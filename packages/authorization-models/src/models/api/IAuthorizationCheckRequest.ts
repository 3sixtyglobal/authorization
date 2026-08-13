// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Request to check an authorization policy.
 */
export interface IAuthorizationCheckRequest {
	/**
	 * The request data.
	 */
	body: {
		/**
		 * The subject to check.
		 */
		subject: string;

		/**
		 * The object to check.
		 */
		object: string;

		/**
		 * The action to check.
		 */
		action: string;
	};
}
