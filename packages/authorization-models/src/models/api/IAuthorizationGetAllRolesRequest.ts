// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Request to get all authorization roles.
 */
export interface IAuthorizationGetAllRolesRequest {
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
		 * The cursor to request the next chunk of results.
		 */
		cursor?: string;

		/**
		 * Limit the number of roles to return.
		 */
		limit?: string;
	};
}
