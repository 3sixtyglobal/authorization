// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IAuthorizationPolicy } from "../IAuthorizationPolicy.js";

/**
 * Request to remove an authorization policy.
 */
export interface IAuthorizationRemovePolicyRequest {
	/**
	 * The request data.
	 */
	body: IAuthorizationPolicy;
}
