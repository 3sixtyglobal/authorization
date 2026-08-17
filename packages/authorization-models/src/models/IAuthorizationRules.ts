// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
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
	 * Role assignments that bind subjects to roles.
	 */
	roleAssignments?: { subject: string; role: string }[];

	/**
	 * Role inheritance relationships between roles.
	 */
	roleInheritances?: { role: string; parentRole: string }[];
}
