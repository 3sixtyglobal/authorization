// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Request to get all authorization policies.
 */
export interface IAuthorizationGetAllPoliciesRequest {
	/**
	 * The optional query parameters.
	 */
	query?: {
		/**
		 * Filter policies by subject.
		 */
		subject?: string;

		/**
		 * The cursor to request the next chunk of results.
		 */
		cursor?: string;

		/**
		 * Limit the number of entities to return.
		 */
		limit?: string;
	};
}
