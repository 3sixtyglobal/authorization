// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Metric IDs for the authorization service.
 */
export const AUTHORIZATION_METRIC_IDS = {
	/**
	 * Metric ID for policy add operations.
	 */
	PoliciesAdded: "authorization_policies_added",

	/**
	 * Metric ID for policy remove operations.
	 */
	PoliciesRemoved: "authorization_policies_removed",

	/**
	 * Metric ID for role assignment operations.
	 */
	RolesAdded: "authorization_roles_added",

	/**
	 * Metric ID for role removal operations.
	 */
	RolesRemoved: "authorization_roles_removed",

	/**
	 * Metric ID for role inheritance add operations.
	 */
	RoleInheritancesAdded: "authorization_role_inheritances_added",

	/**
	 * Metric ID for role inheritance remove operations.
	 */
	RoleInheritancesRemoved: "authorization_role_inheritances_removed"
} as const;

/**
 * Union type of all authorization metric IDs.
 */
export type AuthorizationMetricIds =
	(typeof AUTHORIZATION_METRIC_IDS)[keyof typeof AUTHORIZATION_METRIC_IDS];
