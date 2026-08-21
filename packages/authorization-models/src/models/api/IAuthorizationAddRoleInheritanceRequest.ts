// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Request to add a role inheritance.
 */
export interface IAuthorizationAddRoleInheritanceRequest {
	/**
	 * The request path parameters.
	 */
	pathParams: {
		/**
		 * The role to add the inheritance to.
		 */
		role: string;
	};

	/**
	 * The request data.
	 */
	body: {
		/**
		 * The parent role to inherit from.
		 */
		inheritsFrom: string;
	};
}
