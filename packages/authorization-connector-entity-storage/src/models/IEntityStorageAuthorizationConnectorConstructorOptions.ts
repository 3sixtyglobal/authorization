// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Options for the entity storage authorization connector constructor.
 */
export interface IEntityStorageAuthorizationConnectorConstructorOptions {
	/**
	 * The entity storage type for authorization policies.
	 * @default "authorization-policy"
	 */
	authorizationPolicyEntityStorageType?: string;

	/**
	 * The entity storage type for authorization role assignments.
	 * @default "authorization-role-assignment"
	 */
	authorizationRoleAssignmentEntityStorageType?: string;

	/**
	 * The entity storage type for authorization role inheritance relationships.
	 * @default "authorization-role-inheritance"
	 */
	authorizationRoleInheritanceEntityStorageType?: string;

	/**
	 * The entity storage type for the denormalised role name index.
	 * @default "authorization-role-name"
	 */
	authorizationRoleNameEntityStorageType?: string;
}
