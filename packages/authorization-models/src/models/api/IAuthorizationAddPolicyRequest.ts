// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IAuthorizationPolicy } from "../IAuthorizationPolicy.js";

/**
 * Request to add an authorization policy.
 */
export interface IAuthorizationAddPolicyRequest {
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
	 * The request data.
	 */
	body: IAuthorizationPolicy;
}
