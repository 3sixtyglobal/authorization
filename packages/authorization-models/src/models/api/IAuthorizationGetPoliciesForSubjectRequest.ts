// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Request to get authorization policies for a subject.
 */
export interface IAuthorizationGetPoliciesForSubjectRequest {
	/**
	 * The request path parameters.
	 */
	pathParams: {
		/**
		 * The subject to get policies for.
		 */
		subject: string;
	};
}
