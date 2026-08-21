// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IAuthorizationInheritance } from "./IAuthorizationInheritance.js";
import type { IAuthorizationPolicy } from "./IAuthorizationPolicy.js";

/**
 * Defines multiple authorization rules.
 */
export interface IAuthorizationRules {
	/**
	 * Direct policy rules to apply.
	 */
	policies?: IAuthorizationPolicy[];

	/**
	 * Role inheritance relationships between roles.
	 */
	roleInheritances?: IAuthorizationInheritance[];
}
