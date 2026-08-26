// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Request to get child roles for a role.
 */
export interface IAuthorizationGetChildRolesRequest {
	/**
	 * The request path parameters.
	 */
	pathParams: {
		/**
		 * The model identifier selecting which policy set to use.
		 */
		modelId: string;

		/**
		 * The role to get child roles for.
		 */
		role: string;
	};
}
