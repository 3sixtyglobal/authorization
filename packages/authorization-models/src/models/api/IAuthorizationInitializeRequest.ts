// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IAuthorizationRules } from "../IAuthorizationRules.js";

/**
 * Request to initialize authorization rules.
 */
export interface IAuthorizationInitializeRequest {
	/**
	 * The request data.
	 */
	body: {
		/**
		 * The rules to initialize.
		 */
		rules: IAuthorizationRules[];
	};
}
