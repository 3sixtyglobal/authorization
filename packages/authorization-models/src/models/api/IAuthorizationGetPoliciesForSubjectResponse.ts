// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IAuthorizationPolicy } from "../IAuthorizationPolicy.js";

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
		policies: IAuthorizationPolicy[];
	};
}
