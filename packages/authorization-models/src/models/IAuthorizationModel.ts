// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IAuthorizationInheritance } from "./IAuthorizationInheritance.js";
import type { IAuthorizationPolicy } from "./IAuthorizationPolicy.js";

/**
 * Defines a set of authorization rules as a model.
 */
export interface IAuthorizationModel {
	/**
	 * Direct policy rules to apply.
	 */
	policies?: IAuthorizationPolicy[];

	/**
	 * Role inheritance relationships between roles.
	 */
	roleInheritances?: IAuthorizationInheritance[];
}
