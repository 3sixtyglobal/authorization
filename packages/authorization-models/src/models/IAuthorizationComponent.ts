// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IComponent } from "@twin.org/core";
import type { IAuthorizationPolicy } from "./IAuthorizationPolicy.js";
import type { IAuthorizationRules } from "./IAuthorizationRules.js";

/**
 * Interface describing an authorization component.
 */
export interface IAuthorizationComponent extends IComponent {
	/**
	 * Initialise the component with a default set of rules, applying policies, role assignments, and role inheritances.
	 * @param rules The sets of rules to apply.
	 * @returns A promise that resolves when all rules have been applied.
	 */
	initialize(rules: IAuthorizationRules[]): Promise<void>;

	/**
	 * Check whether a subject is permitted to perform an action on a resource.
	 * @param subject The subject requesting access.
	 * @param object The object being accessed.
	 * @param action The action to check.
	 * @returns True if access is granted, false otherwise.
	 */
	check(subject: string, object: string, action: string): Promise<boolean>;

	/**
	 * Add a policy rule.
	 * @param policy The policy to add.
	 * @returns A promise that resolves when the policy has been added.
	 */
	addPolicy(policy: IAuthorizationPolicy): Promise<void>;

	/**
	 * Remove a policy rule.
	 * @param policy The policy to remove.
	 * @returns A promise that resolves when the policy has been removed.
	 */
	removePolicy(policy: IAuthorizationPolicy): Promise<void>;

	/**
	 * Get all policy rules for a given subject.
	 * @param subject The subject to query.
	 * @returns The matching policies.
	 */
	getPoliciesForSubject(subject: string): Promise<IAuthorizationPolicy[]>;

	/**
	 * Get policy rules, optionally filtered by subject.
	 * @param subject Optional subject to filter by.
	 * @param cursor The cursor to request the next chunk of results.
	 * @param limit Limit the number of entities to return.
	 * @returns The matching policies and an optional cursor for the next page.
	 */
	getAllPolicies(
		subject?: string,
		cursor?: string,
		limit?: number
	): Promise<{ entities: IAuthorizationPolicy[]; cursor?: string }>;

	/**
	 * Get all distinct role names in the system.
	 * @param cursor The cursor to request the next chunk of results.
	 * @param limit Limit the number of roles to return.
	 * @returns The role names and an optional cursor for the next page.
	 */
	getAllRoles(cursor?: string, limit?: number): Promise<{ roles: string[]; cursor?: string }>;

	/**
	 * Assign a role to a subject.
	 * @param subject The subject to assign the role to.
	 * @param role The role to assign.
	 * @returns A promise that resolves when the role has been assigned.
	 */
	addRoleForSubject(subject: string, role: string): Promise<void>;

	/**
	 * Remove a role from a subject.
	 * @param subject The subject to remove the role from.
	 * @param role The role to remove.
	 * @returns A promise that resolves when the role has been removed.
	 */
	removeRoleForSubject(subject: string, role: string): Promise<void>;

	/**
	 * Remove all roles from a subject.
	 * @param subject The subject to remove all roles from.
	 * @returns A promise that resolves when all roles have been removed.
	 */
	removeAllRolesForSubject(subject: string): Promise<void>;

	/**
	 * Get all roles assigned to a subject.
	 * @param subject The subject to query.
	 * @returns The assigned roles.
	 */
	getRolesForSubject(subject: string): Promise<string[]>;

	/**
	 * Get all subjects assigned to a given role.
	 * @param role The role to query.
	 * @returns The subjects with the given role.
	 */
	getSubjectsForRole(role: string): Promise<string[]>;

	/**
	 * Check whether a subject has a specific role.
	 * @param subject The subject to check.
	 * @param role The role to check for.
	 * @returns True if the subject has the role.
	 */
	hasRoleForSubject(subject: string, role: string): Promise<boolean>;

	/**
	 * Define a parent-child inheritance relationship between two roles.
	 * @param role The child role that will inherit permissions from the parent.
	 * @param parentRole The parent role whose permissions are inherited.
	 * @returns A promise that resolves when the role inheritance has been added.
	 */
	addRoleInheritance(role: string, parentRole: string): Promise<void>;

	/**
	 * Remove a parent-child inheritance relationship between two roles.
	 * @param role The child role.
	 * @param parentRole The parent role to stop inheriting from.
	 * @returns A promise that resolves when the role inheritance has been removed.
	 */
	removeRoleInheritance(role: string, parentRole: string): Promise<void>;

	/**
	 * Get all roles that a given role directly inherits from.
	 * @param role The role to query.
	 * @returns The parent roles.
	 */
	getParentRoles(role: string): Promise<string[]>;

	/**
	 * Get all roles that directly inherit from a given role.
	 * @param role The role to query.
	 * @returns The child roles.
	 */
	getChildRoles(role: string): Promise<string[]>;
}
