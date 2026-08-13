// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IAuthorizationPolicy } from "../IAuthorizationPolicy.js";

/**
 * Response for getting all authorization policies.
 */
export interface IAuthorizationGetAllPoliciesResponse {
	/**
	 * The response body.
	 */
	body: {
		/**
		 * The list of policies.
		 */
		entities: IAuthorizationPolicy[];

		/**
		 * An optional cursor, when defined can be used to retrieve the next chunk of results.
		 */
		cursor?: string;
	};
}
