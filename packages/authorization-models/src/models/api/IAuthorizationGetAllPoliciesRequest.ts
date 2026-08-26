// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Request to get all authorization policies.
 */
export interface IAuthorizationGetAllPoliciesRequest {
	/**
	 * The request path parameters.
	 */
	pathParams: {
		/**
		 * The model identifier selecting which policy set to use.
		 */
		modelId: string;
	};

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
