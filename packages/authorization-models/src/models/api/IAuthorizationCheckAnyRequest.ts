// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Request to check an authorization policy for any of a list of subjects.
 */
export interface IAuthorizationCheckAnyRequest {
	/**
	 * The request data.
	 */
	body: {
		/**
		 * The subjects to check.
		 */
		subjects: string[];

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
