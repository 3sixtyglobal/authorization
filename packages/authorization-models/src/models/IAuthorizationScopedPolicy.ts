// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IAuthorizationPolicy } from "./IAuthorizationPolicy.js";

/**
 * A stored authorization policy rule together with the organization it is scoped to.
 */
export interface IAuthorizationScopedPolicy extends IAuthorizationPolicy {
	/**
	 * The organization the policy is scoped to, omitted for a global policy.
	 */
	organization?: string;
}
