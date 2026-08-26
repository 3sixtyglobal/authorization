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
		 * The model identifier selecting which policy set to use.
		 */
		modelId: string;

		/**
		 * The subject to get policies for.
		 */
		subject: string;
	};

	/**
	 * The request query parameters.
	 */
	query?: {
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
