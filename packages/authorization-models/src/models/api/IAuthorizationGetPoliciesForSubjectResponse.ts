// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IAuthorizationScopedPolicy } from "../IAuthorizationScopedPolicy.js";

/**
 * Response for getting authorization policies for a subject.
 */
export interface IAuthorizationGetPoliciesForSubjectResponse {
	/**
	 * The response body.
	 */
	body: {
		/**
		 * The list of policies for the subject.
		 */
		entities: IAuthorizationScopedPolicy[];

		/**
		 * An optional cursor for the next page of results.
		 */
		cursor?: string;
	};
}
