// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Request to remove a role inheritance.
 */
export interface IAuthorizationRemoveRoleInheritanceRequest {
	/**
	 * The request path parameters.
	 */
	pathParams: {
		/**
		 * The model identifier selecting which policy set to use.
		 */
		modelId: string;

		/**
		 * The role to remove the inheritance from.
		 */
		role: string;

		/**
		 * The parent role to remove.
		 */
		inheritsFrom: string;
	};
}
