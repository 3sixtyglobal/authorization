// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { BaseRestClient } from "@twin.org/api-core";
import type { IBaseRestClientConfig, INoContentResponse } from "@twin.org/api-models";
import type {
	IAuthorizationAddPolicyRequest,
	IAuthorizationAddRoleForSubjectRequest,
	IAuthorizationAddRoleInheritanceRequest,
	IAuthorizationCheckRequest,
	IAuthorizationCheckResponse,
	IAuthorizationComponent,
	IAuthorizationGetAllPoliciesRequest,
	IAuthorizationGetAllPoliciesResponse,
	IAuthorizationGetAllRolesRequest,
	IAuthorizationGetAllRolesResponse,
	IAuthorizationGetChildRolesRequest,
	IAuthorizationGetChildRolesResponse,
	IAuthorizationGetParentRolesRequest,
	IAuthorizationGetParentRolesResponse,
	IAuthorizationGetPoliciesForSubjectRequest,
	IAuthorizationGetPoliciesForSubjectResponse,
	IAuthorizationGetRolesForSubjectRequest,
	IAuthorizationGetRolesForSubjectResponse,
	IAuthorizationGetSubjectsForRoleRequest,
	IAuthorizationGetSubjectsForRoleResponse,
	IAuthorizationHasRoleForSubjectRequest,
	IAuthorizationHasRoleForSubjectResponse,
	IAuthorizationPolicy,
	IAuthorizationRemoveAllRolesForSubjectRequest,
	IAuthorizationRemovePolicyRequest,
	IAuthorizationRemoveRoleForSubjectRequest,
	IAuthorizationRemoveRoleInheritanceRequest
} from "@twin.org/authorization-models";
import { Guards } from "@twin.org/core";
import { nameof } from "@twin.org/nameof";
import { HttpMethod } from "@twin.org/web";

/**
 * Client for performing authorization operations through to REST endpoints.
 */
export class AuthorizationRestClient extends BaseRestClient implements IAuthorizationComponent {
	/**
	 * Runtime name for the class.
	 */
	public static readonly CLASS_NAME: string = nameof<AuthorizationRestClient>();

	/**
	 * Create a new instance of AuthorizationRestClient.
	 * @param config The configuration for the client.
	 */
	constructor(config: IBaseRestClientConfig) {
		super(AuthorizationRestClient.CLASS_NAME, config, "authorization");
	}

	/**
	 * Returns the class name of the component.
	 * @returns The class name of the component.
	 */
	public className(): string {
		return AuthorizationRestClient.CLASS_NAME;
	}

	/**
	 * Check whether a subject is permitted to perform an action on a resource.
	 * @param subject The subject requesting access.
	 * @param object The object being accessed.
	 * @param action The action to check.
	 * @returns True if access is granted, false otherwise.
	 */
	public async check(subject: string, object: string, action: string): Promise<boolean> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(object), object);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(action), action);

		const response = await this.fetch<IAuthorizationCheckRequest, IAuthorizationCheckResponse>(
			"/check",
			HttpMethod.POST,
			{ body: { subject, object, action } }
		);

		return response.body.allowed;
	}

	/**
	 * Add a policy rule.
	 * @param policy The policy to add.
	 * @returns Nothing.
	 */
	public async addPolicy(policy: IAuthorizationPolicy): Promise<void> {
		Guards.object(AuthorizationRestClient.CLASS_NAME, nameof(policy), policy);

		await this.fetch<IAuthorizationAddPolicyRequest, INoContentResponse>(
			"/policy",
			HttpMethod.POST,
			{ body: policy }
		);
	}

	/**
	 * Remove a policy rule.
	 * @param policy The policy to remove.
	 * @returns Nothing.
	 */
	public async removePolicy(policy: IAuthorizationPolicy): Promise<void> {
		Guards.object(AuthorizationRestClient.CLASS_NAME, nameof(policy), policy);

		await this.fetch<IAuthorizationRemovePolicyRequest, INoContentResponse>(
			"/policy/remove",
			HttpMethod.POST,
			{ body: policy }
		);
	}

	/**
	 * Get all policy rules for a given subject.
	 * @param subject The subject to query.
	 * @returns The matching policies.
	 */
	public async getPoliciesForSubject(subject: string): Promise<IAuthorizationPolicy[]> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(subject), subject);

		const response = await this.fetch<
			IAuthorizationGetPoliciesForSubjectRequest,
			IAuthorizationGetPoliciesForSubjectResponse
		>("/policy/:subject", HttpMethod.GET, { pathParams: { subject } });

		return response.body.policies;
	}

	/**
	 * Get policy rules, optionally filtered by subject.
	 * @param subject Optional subject to filter by.
	 * @param cursor The cursor to request the next chunk of results.
	 * @param limit Limit the number of entities to return.
	 * @returns The matching policies and an optional cursor for the next page.
	 */
	public async getAllPolicies(
		subject?: string,
		cursor?: string,
		limit?: number
	): Promise<{ entities: IAuthorizationPolicy[]; cursor?: string }> {
		const response = await this.fetch<
			IAuthorizationGetAllPoliciesRequest,
			IAuthorizationGetAllPoliciesResponse
		>("/policy", HttpMethod.GET, {
			query: {
				subject,
				cursor,
				limit: limit !== undefined ? String(limit) : undefined
			}
		});

		return response.body;
	}

	/**
	 * Get all distinct role names in the system.
	 * @param cursor The cursor to request the next chunk of results.
	 * @param limit Limit the number of roles to return.
	 * @returns The role names and an optional cursor for the next page.
	 */
	public async getAllRoles(
		cursor?: string,
		limit?: number
	): Promise<{ roles: string[]; cursor?: string }> {
		const response = await this.fetch<
			IAuthorizationGetAllRolesRequest,
			IAuthorizationGetAllRolesResponse
		>("/roles", HttpMethod.GET, {
			query: {
				cursor,
				limit: limit !== undefined ? String(limit) : undefined
			}
		});

		return response.body;
	}

	/**
	 * Assign a role to a subject.
	 * @param subject The subject to assign the role to.
	 * @param role The role to assign.
	 * @returns Nothing.
	 */
	public async addRoleForSubject(subject: string, role: string): Promise<void> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(role), role);

		await this.fetch<IAuthorizationAddRoleForSubjectRequest, INoContentResponse>(
			"/subject/:subject/role",
			HttpMethod.POST,
			{ pathParams: { subject }, body: { role } }
		);
	}

	/**
	 * Remove a role from a subject.
	 * @param subject The subject to remove the role from.
	 * @param role The role to remove.
	 * @returns Nothing.
	 */
	public async removeRoleForSubject(subject: string, role: string): Promise<void> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(role), role);

		await this.fetch<IAuthorizationRemoveRoleForSubjectRequest, INoContentResponse>(
			"/subject/:subject/role/:role",
			HttpMethod.DELETE,
			{ pathParams: { subject, role } }
		);
	}

	/**
	 * Remove all roles from a subject.
	 * @param subject The subject to remove all roles from.
	 * @returns Nothing.
	 */
	public async removeAllRolesForSubject(subject: string): Promise<void> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(subject), subject);

		await this.fetch<IAuthorizationRemoveAllRolesForSubjectRequest, INoContentResponse>(
			"/subject/:subject/roles",
			HttpMethod.DELETE,
			{ pathParams: { subject } }
		);
	}

	/**
	 * Get all roles assigned to a subject.
	 * @param subject The subject to query.
	 * @returns The assigned roles.
	 */
	public async getRolesForSubject(subject: string): Promise<string[]> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(subject), subject);

		const response = await this.fetch<
			IAuthorizationGetRolesForSubjectRequest,
			IAuthorizationGetRolesForSubjectResponse
		>("/subject/:subject/roles", HttpMethod.GET, { pathParams: { subject } });

		return response.body.roles;
	}

	/**
	 * Get all subjects assigned to a given role.
	 * @param role The role to query.
	 * @returns The subjects with the given role.
	 */
	public async getSubjectsForRole(role: string): Promise<string[]> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(role), role);

		const response = await this.fetch<
			IAuthorizationGetSubjectsForRoleRequest,
			IAuthorizationGetSubjectsForRoleResponse
		>("/role/:role/subjects", HttpMethod.GET, { pathParams: { role } });

		return response.body.subjects;
	}

	/**
	 * Check whether a subject has a specific role.
	 * @param subject The subject to check.
	 * @param role The role to check for.
	 * @returns True if the subject has the role.
	 */
	public async hasRoleForSubject(subject: string, role: string): Promise<boolean> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(role), role);

		const response = await this.fetch<
			IAuthorizationHasRoleForSubjectRequest,
			IAuthorizationHasRoleForSubjectResponse
		>("/subject/:subject/role/:role", HttpMethod.GET, { pathParams: { subject, role } });

		return response.body.hasRole;
	}

	/**
	 * Define a parent-child inheritance relationship between two roles.
	 * @param role The child role that will inherit permissions from the parent.
	 * @param parentRole The parent role whose permissions are inherited.
	 * @returns Nothing.
	 */
	public async addRoleInheritance(role: string, parentRole: string): Promise<void> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(role), role);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(parentRole), parentRole);

		await this.fetch<IAuthorizationAddRoleInheritanceRequest, INoContentResponse>(
			"/role/:role/inherit",
			HttpMethod.POST,
			{ pathParams: { role }, body: { parentRole } }
		);
	}

	/**
	 * Remove a parent-child inheritance relationship between two roles.
	 * @param role The child role.
	 * @param parentRole The parent role to stop inheriting from.
	 * @returns Nothing.
	 */
	public async removeRoleInheritance(role: string, parentRole: string): Promise<void> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(role), role);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(parentRole), parentRole);

		await this.fetch<IAuthorizationRemoveRoleInheritanceRequest, INoContentResponse>(
			"/role/:role/inherit/:parentRole",
			HttpMethod.DELETE,
			{ pathParams: { role, parentRole } }
		);
	}

	/**
	 * Get all roles that a given role directly inherits from.
	 * @param role The role to query.
	 * @returns The parent roles.
	 */
	public async getParentRoles(role: string): Promise<string[]> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(role), role);

		const response = await this.fetch<
			IAuthorizationGetParentRolesRequest,
			IAuthorizationGetParentRolesResponse
		>("/role/:role/parents", HttpMethod.GET, { pathParams: { role } });

		return response.body.roles;
	}

	/**
	 * Get all roles that directly inherit from a given role.
	 * @param role The role to query.
	 * @returns The child roles.
	 */
	public async getChildRoles(role: string): Promise<string[]> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(role), role);

		const response = await this.fetch<
			IAuthorizationGetChildRolesRequest,
			IAuthorizationGetChildRolesResponse
		>("/role/:role/children", HttpMethod.GET, { pathParams: { role } });

		return response.body.roles;
	}
}
