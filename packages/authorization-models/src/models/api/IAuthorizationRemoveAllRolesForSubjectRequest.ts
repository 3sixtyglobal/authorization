// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Request to remove all roles for a subject.
 */
export interface IAuthorizationRemoveAllRolesForSubjectRequest {
	/**
	 * The request path parameters.
	 */
	pathParams: {
		/**
		 * The model identifier selecting which policy set to use.
		 */
		modelId: string;

		/**
		 * The subject to remove all roles from.
		 */
		subject: string;
	};
}
