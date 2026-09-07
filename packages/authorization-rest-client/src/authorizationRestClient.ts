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
	IAuthorizationHasRolesRequest,
	IAuthorizationHasRolesResponse,
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
	IAuthorizationScopedPolicy,
	IAuthorizationBuildRequest,
	IAuthorizationModel,
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
	 * Build the authorization model by applying a set of policies and role inheritances.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param model The policies and role inheritances to apply.
	 * @returns Nothing.
	 */
	public async build(modelId: string, model: IAuthorizationModel): Promise<void> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(modelId), modelId);

		await this.fetch<IAuthorizationBuildRequest, never>("/:modelId", HttpMethod.POST, {
			pathParams: { modelId },
			body: model
		});
	}

	/**
	 * Check whether a subject is permitted to perform an action on a resource.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject requesting access.
	 * @param object The object being accessed.
	 * @param action The action to check.
	 * @returns True if access is granted, false otherwise.
	 */
	public async check(
		modelId: string,
		subject: string,
		object: string,
		action: string
	): Promise<boolean> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(object), object);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(action), action);

		const response = await this.fetch<IAuthorizationCheckRequest, IAuthorizationCheckResponse>(
			"/:modelId/check",
			HttpMethod.POST,
			{ pathParams: { modelId }, body: { subject, object, action } }
		);

		return response.body.allowed;
	}

	/**
	 * Add a policy rule.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject the policy applies to.
	 * @param object The object the policy applies to.
	 * @param action The action the policy applies to.
	 * @returns Nothing.
	 */
	public async addPolicy(
		modelId: string,
		subject: string,
		object: string,
		action: string
	): Promise<void> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(object), object);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(action), action);

		await this.fetch<IAuthorizationAddPolicyRequest, INoContentResponse>(
			"/:modelId/policy",
			HttpMethod.POST,
			{ pathParams: { modelId }, body: { subject, object, action } }
		);
	}

	/**
	 * Remove a policy rule.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject of the policy to remove.
	 * @param object The object of the policy to remove.
	 * @param action The action of the policy to remove.
	 * @returns Nothing.
	 */
	public async removePolicy(
		modelId: string,
		subject: string,
		object: string,
		action: string
	): Promise<void> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(object), object);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(action), action);

		await this.fetch<IAuthorizationRemovePolicyRequest, INoContentResponse>(
			"/:modelId/policy/remove",
			HttpMethod.POST,
			{ pathParams: { modelId }, body: { subject, object, action } }
		);
	}

	/**
	 * Get all policy rules for a given subject.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject to query.
	 * @param cursor The cursor to request the next chunk of results.
	 * @param limit Limit the number of entities to return.
	 * @returns The matching policies and an optional cursor for the next page.
	 */
	public async getPoliciesForSubject(
		modelId: string,
		subject: string,
		cursor?: string,
		limit?: number
	): Promise<{ entities: IAuthorizationScopedPolicy[]; cursor?: string }> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(subject), subject);

		const response = await this.fetch<
			IAuthorizationGetPoliciesForSubjectRequest,
			IAuthorizationGetPoliciesForSubjectResponse
		>("/:modelId/policy/:subject", HttpMethod.GET, {
			pathParams: { modelId, subject },
			query: { cursor, limit: limit !== undefined ? String(limit) : undefined }
		});

		return response.body;
	}

	/**
	 * Get policy rules, optionally filtered by subject.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject Optional subject to filter by.
	 * @param cursor The cursor to request the next chunk of results.
	 * @param limit Limit the number of entities to return.
	 * @returns The matching policies and an optional cursor for the next page.
	 */
	public async getAllPolicies(
		modelId: string,
		subject?: string,
		cursor?: string,
		limit?: number
	): Promise<{ entities: IAuthorizationScopedPolicy[]; cursor?: string }> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(modelId), modelId);

		const response = await this.fetch<
			IAuthorizationGetAllPoliciesRequest,
			IAuthorizationGetAllPoliciesResponse
		>("/:modelId/policy", HttpMethod.GET, {
			pathParams: { modelId },
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
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param cursor The cursor to request the next chunk of results.
	 * @param limit Limit the number of roles to return.
	 * @returns The role names and an optional cursor for the next page.
	 */
	public async getAllRoles(
		modelId: string,
		cursor?: string,
		limit?: number
	): Promise<{ roles: string[]; cursor?: string }> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(modelId), modelId);

		const response = await this.fetch<
			IAuthorizationGetAllRolesRequest,
			IAuthorizationGetAllRolesResponse
		>("/:modelId/roles", HttpMethod.GET, {
			pathParams: { modelId },
			query: {
				cursor,
				limit: limit !== undefined ? String(limit) : undefined
			}
		});

		return response.body;
	}

	/**
	 * Check whether each of the given role names exists in the system.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param roles The role names to check.
	 * @returns An array of booleans in the same order as the input.
	 */
	public async hasRoles(modelId: string, roles: string[]): Promise<boolean[]> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(modelId), modelId);
		Guards.array<string>(AuthorizationRestClient.CLASS_NAME, nameof(roles), roles);

		const response = await this.fetch<
			IAuthorizationHasRolesRequest,
			IAuthorizationHasRolesResponse
		>("/:modelId/roles/has", HttpMethod.POST, { pathParams: { modelId }, body: { roles } });

		return response.body.exists;
	}

	/**
	 * Assign a role to a subject.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject to assign the role to.
	 * @param role The role to assign.
	 * @returns Nothing.
	 */
	public async addRoleForSubject(modelId: string, subject: string, role: string): Promise<void> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(role), role);

		await this.fetch<IAuthorizationAddRoleForSubjectRequest, INoContentResponse>(
			"/:modelId/subject/:subject/role",
			HttpMethod.POST,
			{ pathParams: { modelId, subject }, body: { role } }
		);
	}

	/**
	 * Remove a role from a subject.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject to remove the role from.
	 * @param role The role to remove.
	 * @returns Nothing.
	 */
	public async removeRoleForSubject(modelId: string, subject: string, role: string): Promise<void> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(role), role);

		await this.fetch<IAuthorizationRemoveRoleForSubjectRequest, INoContentResponse>(
			"/:modelId/subject/:subject/role/:role",
			HttpMethod.DELETE,
			{ pathParams: { modelId, subject, role } }
		);
	}

	/**
	 * Remove all roles from a subject.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject to remove all roles from.
	 * @returns Nothing.
	 */
	public async removeAllRolesForSubject(modelId: string, subject: string): Promise<void> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(subject), subject);

		await this.fetch<IAuthorizationRemoveAllRolesForSubjectRequest, INoContentResponse>(
			"/:modelId/subject/:subject/roles",
			HttpMethod.DELETE,
			{ pathParams: { modelId, subject } }
		);
	}

	/**
	 * Get all roles assigned to a subject.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject to query.
	 * @returns The assigned roles.
	 */
	public async getRolesForSubject(modelId: string, subject: string): Promise<string[]> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(subject), subject);

		const response = await this.fetch<
			IAuthorizationGetRolesForSubjectRequest,
			IAuthorizationGetRolesForSubjectResponse
		>("/:modelId/subject/:subject/roles", HttpMethod.GET, { pathParams: { modelId, subject } });

		return response.body.roles;
	}

	/**
	 * Get all subjects assigned to a given role.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param role The role to query.
	 * @returns The subjects with the given role.
	 */
	public async getSubjectsForRole(modelId: string, role: string): Promise<string[]> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(role), role);

		const response = await this.fetch<
			IAuthorizationGetSubjectsForRoleRequest,
			IAuthorizationGetSubjectsForRoleResponse
		>("/:modelId/role/:role/subjects", HttpMethod.GET, { pathParams: { modelId, role } });

		return response.body.subjects;
	}

	/**
	 * Check whether a subject has a specific role.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject to check.
	 * @param role The role to check for.
	 * @returns True if the subject has the role.
	 */
	public async hasRoleForSubject(modelId: string, subject: string, role: string): Promise<boolean> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(role), role);

		const response = await this.fetch<
			IAuthorizationHasRoleForSubjectRequest,
			IAuthorizationHasRoleForSubjectResponse
		>("/:modelId/subject/:subject/role/:role", HttpMethod.GET, {
			pathParams: { modelId, subject, role }
		});

		return response.body.hasRole;
	}

	/**
	 * Define a parent-child inheritance relationship between two roles.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param role The child role that will inherit permissions from the parent.
	 * @param inheritsFrom The parent role whose permissions are inherited.
	 * @returns Nothing.
	 */
	public async addRoleInheritance(
		modelId: string,
		role: string,
		inheritsFrom: string
	): Promise<void> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(role), role);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(inheritsFrom), inheritsFrom);

		await this.fetch<IAuthorizationAddRoleInheritanceRequest, INoContentResponse>(
			"/:modelId/role/:role/inherit",
			HttpMethod.POST,
			{ pathParams: { modelId, role }, body: { inheritsFrom } }
		);
	}

	/**
	 * Remove a parent-child inheritance relationship between two roles.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param role The child role.
	 * @param inheritsFrom The parent role to stop inheriting from.
	 * @returns Nothing.
	 */
	public async removeRoleInheritance(
		modelId: string,
		role: string,
		inheritsFrom: string
	): Promise<void> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(role), role);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(inheritsFrom), inheritsFrom);

		await this.fetch<IAuthorizationRemoveRoleInheritanceRequest, INoContentResponse>(
			"/:modelId/role/:role/inherit/:inheritsFrom",
			HttpMethod.DELETE,
			{ pathParams: { modelId, role, inheritsFrom } }
		);
	}

	/**
	 * Get all roles that a given role directly inherits from.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param role The role to query.
	 * @returns The parent roles.
	 */
	public async getParentRoles(modelId: string, role: string): Promise<string[]> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(role), role);

		const response = await this.fetch<
			IAuthorizationGetParentRolesRequest,
			IAuthorizationGetParentRolesResponse
		>("/:modelId/role/:role/parents", HttpMethod.GET, { pathParams: { modelId, role } });

		return response.body.roles;
	}

	/**
	 * Get all roles that directly inherit from a given role.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param role The role to query.
	 * @returns The child roles.
	 */
	public async getChildRoles(modelId: string, role: string): Promise<string[]> {
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationRestClient.CLASS_NAME, nameof(role), role);

		const response = await this.fetch<
			IAuthorizationGetChildRolesRequest,
			IAuthorizationGetChildRolesResponse
		>("/:modelId/role/:role/children", HttpMethod.GET, { pathParams: { modelId, role } });

		return response.body.roles;
	}
}
