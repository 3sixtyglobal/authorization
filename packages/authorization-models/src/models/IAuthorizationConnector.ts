// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IComponent } from "@twin.org/core";
import type { IAuthorizationModel } from "./IAuthorizationModel.js";
import type { IAuthorizationScopedPolicy } from "./IAuthorizationScopedPolicy.js";

/**
 * Interface describing an authorization connector.
 *
 * Rules are scoped by the ambient tenant and organization context ids, not by parameters:
 * writes stamp the current organization, reads see global plus current, removals match it exactly.
 * Role names aren't scoped. See docs/architecture/rbac-configuration.md.
 */
export interface IAuthorizationConnector extends IComponent {
	/**
	 * Build the authorization model by applying a set of policies and role inheritances.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param model The policies and role inheritances to apply.
	 * @returns A promise that resolves when the model has been built.
	 */
	build(modelId: string, model: IAuthorizationModel): Promise<void>;

	/**
	 * Check whether a subject is permitted to perform an action on a resource.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject requesting access.
	 * @param object The object being accessed.
	 * @param action The action to check.
	 * @returns True if access is granted, false otherwise.
	 */
	check(modelId: string, subject: string, object: string, action: string): Promise<boolean>;

	/**
	 * Add a policy rule.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject the policy applies to.
	 * @param object The object the policy applies to.
	 * @param action The action the policy applies to.
	 * @returns A promise that resolves when the policy has been added.
	 */
	addPolicy(modelId: string, subject: string, object: string, action: string): Promise<void>;

	/**
	 * Remove a policy rule.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject of the policy to remove.
	 * @param object The object of the policy to remove.
	 * @param action The action of the policy to remove.
	 * @returns A promise that resolves when the policy has been removed.
	 */
	removePolicy(modelId: string, subject: string, object: string, action: string): Promise<void>;

	/**
	 * Get all policy rules for a given subject.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject to query.
	 * @param cursor The cursor to request the next chunk of results.
	 * @param limit Limit the number of entities to return.
	 * @returns The matching policies and an optional cursor for the next page.
	 */
	getPoliciesForSubject(
		modelId: string,
		subject: string,
		cursor?: string,
		limit?: number
	): Promise<{ entities: IAuthorizationScopedPolicy[]; cursor?: string }>;

	/**
	 * Get policy rules, optionally filtered by subject.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject Optional subject to filter by.
	 * @param cursor The cursor to request the next chunk of results.
	 * @param limit Limit the number of entities to return.
	 * @returns The matching policies and an optional cursor for the next page.
	 */
	getAllPolicies(
		modelId: string,
		subject?: string,
		cursor?: string,
		limit?: number
	): Promise<{ entities: IAuthorizationScopedPolicy[]; cursor?: string }>;

	/**
	 * Get all distinct role names in the system.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param cursor The cursor to request the next chunk of results.
	 * @param limit Limit the number of roles to return.
	 * @returns The role names and an optional cursor for the next page.
	 */
	getAllRoles(
		modelId: string,
		cursor?: string,
		limit?: number
	): Promise<{ roles: string[]; cursor?: string }>;

	/**
	 * Check whether each of the given role names exists in the system.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param roles The role names to check.
	 * @returns An array of booleans in the same order as the input.
	 */
	hasRoles(modelId: string, roles: string[]): Promise<boolean[]>;

	/**
	 * Assign a role to a subject.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject to assign the role to.
	 * @param role The role to assign.
	 * @returns A promise that resolves when the role has been assigned.
	 */
	addRoleForSubject(modelId: string, subject: string, role: string): Promise<void>;

	/**
	 * Remove a role from a subject.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject to remove the role from.
	 * @param role The role to remove.
	 * @returns A promise that resolves when the role has been removed.
	 */
	removeRoleForSubject(modelId: string, subject: string, role: string): Promise<void>;

	/**
	 * Remove all roles from a subject.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject to remove all roles from.
	 * @returns A promise that resolves when all roles have been removed.
	 */
	removeAllRolesForSubject(modelId: string, subject: string): Promise<void>;

	/**
	 * Get all roles assigned to a subject.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject to query.
	 * @returns The assigned roles.
	 */
	getRolesForSubject(modelId: string, subject: string): Promise<string[]>;

	/**
	 * Get all subjects assigned to a given role.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param role The role to query.
	 * @returns The subjects with the given role.
	 */
	getSubjectsForRole(modelId: string, role: string): Promise<string[]>;

	/**
	 * Check whether a subject has a specific role.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject to check.
	 * @param role The role to check for.
	 * @returns True if the subject has the role.
	 */
	hasRoleForSubject(modelId: string, subject: string, role: string): Promise<boolean>;

	/**
	 * Define a parent-child inheritance relationship between two roles.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param role The child role that will inherit permissions from the parent.
	 * @param inheritsFrom The parent role whose permissions are inherited.
	 * @returns A promise that resolves when the role inheritance has been added.
	 */
	addRoleInheritance(modelId: string, role: string, inheritsFrom: string): Promise<void>;

	/**
	 * Remove a parent-child inheritance relationship between two roles.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param role The child role.
	 * @param inheritsFrom The parent role to stop inheriting from.
	 * @returns A promise that resolves when the role inheritance has been removed.
	 */
	removeRoleInheritance(modelId: string, role: string, inheritsFrom: string): Promise<void>;

	/**
	 * Get all roles that a given role directly inherits from.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param role The role to query.
	 * @returns The parent roles.
	 */
	getParentRoles(modelId: string, role: string): Promise<string[]>;

	/**
	 * Get all roles that directly inherit from a given role.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param role The role to query.
	 * @returns The child roles.
	 */
	getChildRoles(modelId: string, role: string): Promise<string[]>;
}
