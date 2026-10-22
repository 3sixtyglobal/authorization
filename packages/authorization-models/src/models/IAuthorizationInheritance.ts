// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Defines a single role inheritance relationship.
 */
export interface IAuthorizationInheritance {
	/**
	 * The role.
	 */
	role: string;

	/**
	 * The role that this role inherits from.
	 */
	inheritsFrom: string;
}
