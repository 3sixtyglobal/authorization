// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type {
	IAuthorizationConnector,
	IAuthorizationModel,
	IAuthorizationPolicy
} from "@3sixty/authorization-models";
import { BaseError, GeneralError, Guards, Is } from "@3sixty/core";
import {
	ComparisonOperator,
	type EntityCondition,
	LogicalOperator,
	SortDirection
} from "@3sixty/entity";
import {
	EntityStorageConnectorFactory,
	type IEntityStorageConnector
} from "@3sixty/entity-storage-models";
import { nameof } from "@3sixty/nameof";
import { AuthorizationPolicy } from "./entities/authorizationPolicy.js";
import { AuthorizationRoleAssignment } from "./entities/authorizationRoleAssignment.js";
import { AuthorizationRoleInheritance } from "./entities/authorizationRoleInheritance.js";
import { AuthorizationRoleName } from "./entities/authorizationRoleName.js";
import type { IEntityStorageAuthorizationConnectorConstructorOptions } from "./models/IEntityStorageAuthorizationConnectorConstructorOptions.js";

/**
 * A connector that implements the IAuthorizationConnector interface using Entity Storage for authorization.
 */
export class EntityStorageAuthorizationConnector implements IAuthorizationConnector {
	/**
	 * The namespace for the connector.
	 */
	public static readonly NAMESPACE: string = "entity-storage";

	/**
	 * Runtime name for the class.
	 */
	public static readonly CLASS_NAME: string = nameof<EntityStorageAuthorizationConnector>();

	/**
	 * The entity storage for authorization policies.
	 * @internal
	 */
	private readonly _authorizationPolicyEntityStorage: IEntityStorageConnector<AuthorizationPolicy>;

	/**
	 * The entity storage for authorization role assignments.
	 * @internal
	 */
	private readonly _authorizationRoleAssignmentEntityStorage: IEntityStorageConnector<AuthorizationRoleAssignment>;

	/**
	 * The entity storage for authorization role inheritance relationships.
	 * @internal
	 */
	private readonly _authorizationRoleInheritanceEntityStorage: IEntityStorageConnector<AuthorizationRoleInheritance>;

	/**
	 * The entity storage for the denormalised role name index.
	 * @internal
	 */
	private readonly _authorizationRoleNameEntityStorage: IEntityStorageConnector<AuthorizationRoleName>;

	/**
	 * Create a new instance of EntityStorageAuthorizationConnector.
	 * @param options The dependencies for the class.
	 */
	constructor(options?: IEntityStorageAuthorizationConnectorConstructorOptions) {
		this._authorizationPolicyEntityStorage = EntityStorageConnectorFactory.get(
			options?.authorizationPolicyEntityStorageType ?? "authorization-policy"
		);
		this._authorizationRoleAssignmentEntityStorage = EntityStorageConnectorFactory.get(
			options?.authorizationRoleAssignmentEntityStorageType ?? "authorization-role-assignment"
		);
		this._authorizationRoleInheritanceEntityStorage = EntityStorageConnectorFactory.get(
			options?.authorizationRoleInheritanceEntityStorageType ?? "authorization-role-inheritance"
		);
		this._authorizationRoleNameEntityStorage = EntityStorageConnectorFactory.get(
			options?.authorizationRoleNameEntityStorageType ?? "authorization-role-name"
		);
	}

	/**
	 * Returns the class name of the component.
	 * @returns The class name of the component.
	 */
	public className(): string {
		return EntityStorageAuthorizationConnector.CLASS_NAME;
	}

	/**
	 * Build the authorization model by applying a set of policies and role inheritances.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param model The policies and role inheritances to apply.
	 * @returns Nothing.
	 */
	public async build(modelId: string, model: IAuthorizationModel): Promise<void> {
		this.guardNoSeparator(nameof(modelId), modelId);

		try {
			for (const policy of model.policies ?? []) {
				await this.addPolicy(modelId, policy.subject, policy.object, policy.action);
			}
			for (const inheritance of model.roleInheritances ?? []) {
				await this.addRoleInheritance(modelId, inheritance.role, inheritance.inheritsFrom);
			}
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				EntityStorageAuthorizationConnector.CLASS_NAME,
				"buildFailed",
				undefined,
				err
			);
		}
	}

	/**
	 * Check whether a subject is permitted to perform an action on a object.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject requesting access.
	 * @param object The object being accessed.
	 * @param action The action to check.
	 * @returns True if access is granted, false otherwise.
	 * @throws GeneralError if the check request fails.
	 */
	public async check(
		modelId: string,
		subject: string,
		object: string,
		action: string
	): Promise<boolean> {
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(subject), subject);
		this.guardNoSeparator(nameof(object), object);
		this.guardNoSeparator(nameof(action), action);

		try {
			const directPolicy = await this._authorizationPolicyEntityStorage.get(
				this.policyId(modelId, subject, object, action)
			);
			if (directPolicy) {
				return true;
			}

			// Each level of the role graph is resolved with a single join against the policies, so
			// the number of requests grows with the depth of the inheritance not the number of roles.
			let level = await this.joinRolePolicies(
				this._authorizationRoleAssignmentEntityStorage,
				"role",
				{
					logicalOperator: LogicalOperator.And,
					conditions: [
						{ property: "modelId", value: modelId, comparison: ComparisonOperator.Equals },
						{ property: "subject", value: subject, comparison: ComparisonOperator.Equals }
					]
				},
				modelId,
				object,
				action
			);
			const visited = new Set<string>();

			while (!level.granted) {
				const frontier = [...new Set(level.roles)].filter(r => !visited.has(r));
				if (frontier.length === 0) {
					return false;
				}
				for (const r of frontier) {
					visited.add(r);
				}

				level = await this.joinRolePolicies(
					this._authorizationRoleInheritanceEntityStorage,
					"inheritsFrom",
					{
						logicalOperator: LogicalOperator.And,
						conditions: [
							{ property: "modelId", value: modelId, comparison: ComparisonOperator.Equals },
							{ property: "role", value: frontier, comparison: ComparisonOperator.In }
						]
					},
					modelId,
					object,
					action
				);
			}

			return true;
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				EntityStorageAuthorizationConnector.CLASS_NAME,
				"checkFailed",
				{ subject, object, action },
				err
			);
		}
	}

	/**
	 * Add a policy rule.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject the policy applies to.
	 * @param object The object the policy applies to.
	 * @param action The action the policy applies to.
	 * @returns Nothing.
	 * @throws GeneralError if the add request fails.
	 */
	public async addPolicy(
		modelId: string,
		subject: string,
		object: string,
		action: string
	): Promise<void> {
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(subject), subject);
		this.guardNoSeparator(nameof(object), object);
		this.guardNoSeparator(nameof(action), action);
		const id = this.policyId(modelId, subject, object, action);
		this.guardIdLength(this._authorizationPolicyEntityStorage, id);

		try {
			const entity = new AuthorizationPolicy();
			entity.id = id;
			entity.modelId = modelId;
			entity.subject = subject;
			entity.object = object;
			entity.action = action;
			await this._authorizationPolicyEntityStorage.set(entity);
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				EntityStorageAuthorizationConnector.CLASS_NAME,
				"addPolicyFailed",
				{ subject },
				err
			);
		}
	}

	/**
	 * Remove a policy rule.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject of the policy to remove.
	 * @param object The object of the policy to remove.
	 * @param action The action of the policy to remove.
	 * @returns Nothing.
	 * @throws GeneralError if the remove request fails.
	 */
	public async removePolicy(
		modelId: string,
		subject: string,
		object: string,
		action: string
	): Promise<void> {
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(subject), subject);
		this.guardNoSeparator(nameof(object), object);
		this.guardNoSeparator(nameof(action), action);

		try {
			await this._authorizationPolicyEntityStorage.remove(
				this.policyId(modelId, subject, object, action)
			);
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				EntityStorageAuthorizationConnector.CLASS_NAME,
				"removePolicyFailed",
				{ subject },
				err
			);
		}
	}

	/**
	 * Get all policy rules for a given subject.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject to query.
	 * @param cursor The cursor to request the next chunk of results.
	 * @param limit Limit the number of entities to return.
	 * @returns The matching policies and an optional cursor for the next page.
	 * @throws GeneralError if the query fails.
	 */
	public async getPoliciesForSubject(
		modelId: string,
		subject: string,
		cursor?: string,
		limit?: number
	): Promise<{ entities: IAuthorizationPolicy[]; cursor?: string }> {
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(subject), subject);

		try {
			return await this.getAllPolicies(modelId, subject, cursor, limit);
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				EntityStorageAuthorizationConnector.CLASS_NAME,
				"getPoliciesForSubjectFailed",
				{ subject },
				err
			);
		}
	}

	/**
	 * Get policy rules, optionally filtered by subject.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject Optional subject to filter by.
	 * @param cursor The cursor to request the next chunk of results.
	 * @param limit Limit the number of entities to return.
	 * @returns The matching policies and an optional cursor for the next page.
	 * @throws GeneralError if the query fails.
	 */
	public async getAllPolicies(
		modelId: string,
		subject?: string,
		cursor?: string,
		limit?: number
	): Promise<{ entities: IAuthorizationPolicy[]; cursor?: string }> {
		this.guardNoSeparator(nameof(modelId), modelId);
		if (subject !== undefined) {
			this.guardNoSeparator(nameof(subject), subject);
		}

		try {
			const result = await this._authorizationPolicyEntityStorage.query(
				Is.stringValue(subject)
					? {
							logicalOperator: LogicalOperator.And,
							conditions: [
								{ property: "modelId", value: modelId, comparison: ComparisonOperator.Equals },
								{ property: "subject", value: subject, comparison: ComparisonOperator.Equals }
							]
						}
					: { property: "modelId", value: modelId, comparison: ComparisonOperator.Equals },
				undefined,
				undefined,
				cursor,
				limit
			);
			return {
				entities: (result.entities as AuthorizationPolicy[]).map(e => ({
					subject: e.subject,
					object: e.object,
					action: e.action
				})),
				cursor: result.cursor
			};
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				EntityStorageAuthorizationConnector.CLASS_NAME,
				"getAllPoliciesFailed",
				undefined,
				err
			);
		}
	}

	/**
	 * Get all distinct role names in the system.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param cursor The cursor to request the next chunk of results.
	 * @param limit Limit the number of roles to return.
	 * @returns The role names and an optional cursor for the next page.
	 * @throws GeneralError if the query fails.
	 */
	public async getAllRoles(
		modelId: string,
		cursor?: string,
		limit?: number
	): Promise<{ roles: string[]; cursor?: string }> {
		this.guardNoSeparator(nameof(modelId), modelId);

		try {
			const result = await this._authorizationRoleNameEntityStorage.query(
				{ property: "modelId", value: modelId, comparison: ComparisonOperator.Equals },
				[{ property: "name", sortDirection: SortDirection.Ascending }],
				["name"],
				cursor,
				limit
			);
			return {
				roles: result.entities.map(e => e.name).filter((r): r is string => r !== undefined),
				cursor: result.cursor
			};
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				EntityStorageAuthorizationConnector.CLASS_NAME,
				"getAllRolesFailed",
				undefined,
				err
			);
		}
	}

	/**
	 * Check whether each of the given role names exists in the system.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param roles The role names to check.
	 * @returns An array of booleans in the same order as the input.
	 * @throws GeneralError if the query fails.
	 */
	public async hasRoles(modelId: string, roles: string[]): Promise<boolean[]> {
		this.guardNoSeparator(nameof(modelId), modelId);
		Guards.array<string>(EntityStorageAuthorizationConnector.CLASS_NAME, nameof(roles), roles);
		for (const role of roles) {
			this.guardNoSeparator(nameof(role), role);
		}

		try {
			const ids = [...new Set(roles.map(role => this.roleNameId(modelId, role)))];
			const found = new Set(
				await this.queryAllValues(
					this._authorizationRoleNameEntityStorage,
					{ property: "id", value: ids, comparison: ComparisonOperator.In },
					"id"
				)
			);
			return roles.map(role => found.has(this.roleNameId(modelId, role)));
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				EntityStorageAuthorizationConnector.CLASS_NAME,
				"hasRolesFailed",
				undefined,
				err
			);
		}
	}

	/**
	 * Assign a role to a subject.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject to assign the role to.
	 * @param role The role to assign.
	 * @returns Nothing.
	 * @throws GeneralError if the request fails.
	 */
	public async addRoleForSubject(modelId: string, subject: string, role: string): Promise<void> {
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(subject), subject);
		this.guardNoSeparator(nameof(role), role);
		const id = this.roleId(modelId, subject, role);
		this.guardIdLength(this._authorizationRoleAssignmentEntityStorage, id);
		const roleName = this.createRoleName(modelId, role);

		try {
			const assignment = new AuthorizationRoleAssignment();
			assignment.id = id;
			assignment.modelId = modelId;
			assignment.subject = subject;
			assignment.role = role;
			// Write the name first so a failure leaves at worst a stale name, never an unlisted grant.
			await this._authorizationRoleNameEntityStorage.set(roleName);
			await this._authorizationRoleAssignmentEntityStorage.set(assignment);
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				EntityStorageAuthorizationConnector.CLASS_NAME,
				"addRoleForSubjectFailed",
				{ subject, role },
				err
			);
		}
	}

	/**
	 * Remove a role from a subject.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject to remove the role from.
	 * @param role The role to remove.
	 * @returns Nothing.
	 * @throws GeneralError if the request fails.
	 */
	public async removeRoleForSubject(modelId: string, subject: string, role: string): Promise<void> {
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(subject), subject);
		this.guardNoSeparator(nameof(role), role);

		try {
			await this._authorizationRoleAssignmentEntityStorage.remove(
				this.roleId(modelId, subject, role)
			);
			await this.removeRoleNameIfUnreferenced(modelId, role);
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				EntityStorageAuthorizationConnector.CLASS_NAME,
				"removeRoleForSubjectFailed",
				{ subject, role },
				err
			);
		}
	}

	/**
	 * Remove all roles from a subject.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject to remove all roles from.
	 * @returns Nothing.
	 * @throws GeneralError if the request fails.
	 */
	public async removeAllRolesForSubject(modelId: string, subject: string): Promise<void> {
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(subject), subject);

		try {
			const roles = new Set<string>();
			let hasMore: boolean;
			// Always read the first page, as removing a page invalidates any offset based cursor.
			do {
				const result = await this._authorizationRoleAssignmentEntityStorage.query(
					{
						logicalOperator: LogicalOperator.And,
						conditions: [
							{ property: "modelId", value: modelId, comparison: ComparisonOperator.Equals },
							{ property: "subject", value: subject, comparison: ComparisonOperator.Equals }
						]
					},
					undefined,
					["id", "role"]
				);
				const ids = result.entities.map(e => e.id).filter((id): id is string => id !== undefined);
				for (const entity of result.entities) {
					if (Is.stringValue(entity.role)) {
						roles.add(entity.role);
					}
				}
				if (ids.length > 0) {
					await this._authorizationRoleAssignmentEntityStorage.removeBatch(ids);
				}
				hasMore = ids.length > 0 && Is.stringValue(result.cursor);
			} while (hasMore);

			for (const role of roles) {
				await this.removeRoleNameIfUnreferenced(modelId, role);
			}
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				EntityStorageAuthorizationConnector.CLASS_NAME,
				"removeAllRolesForSubjectFailed",
				{ subject },
				err
			);
		}
	}

	/**
	 * Get all roles assigned to a subject.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject to query.
	 * @returns The assigned roles.
	 * @throws GeneralError if the query fails.
	 */
	public async getRolesForSubject(modelId: string, subject: string): Promise<string[]> {
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(subject), subject);

		try {
			return await this.queryAllValues(
				this._authorizationRoleAssignmentEntityStorage,
				{
					logicalOperator: LogicalOperator.And,
					conditions: [
						{ property: "modelId", value: modelId, comparison: ComparisonOperator.Equals },
						{ property: "subject", value: subject, comparison: ComparisonOperator.Equals }
					]
				},
				"role"
			);
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				EntityStorageAuthorizationConnector.CLASS_NAME,
				"getRolesForSubjectFailed",
				{ subject },
				err
			);
		}
	}

	/**
	 * Get all subjects assigned to a given role.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param role The role to query.
	 * @returns The subjects with the given role.
	 * @throws GeneralError if the query fails.
	 */
	public async getSubjectsForRole(modelId: string, role: string): Promise<string[]> {
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(role), role);

		try {
			return await this.queryAllValues(
				this._authorizationRoleAssignmentEntityStorage,
				{
					logicalOperator: LogicalOperator.And,
					conditions: [
						{ property: "modelId", value: modelId, comparison: ComparisonOperator.Equals },
						{ property: "role", value: role, comparison: ComparisonOperator.Equals }
					]
				},
				"subject"
			);
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				EntityStorageAuthorizationConnector.CLASS_NAME,
				"getSubjectsForRoleFailed",
				{ role },
				err
			);
		}
	}

	/**
	 * Check whether a subject has a specific role.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject to check.
	 * @param role The role to check for.
	 * @returns True if the subject has the role.
	 * @throws GeneralError if the request fails.
	 */
	public async hasRoleForSubject(modelId: string, subject: string, role: string): Promise<boolean> {
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(subject), subject);
		this.guardNoSeparator(nameof(role), role);

		try {
			const entity = await this._authorizationRoleAssignmentEntityStorage.get(
				this.roleId(modelId, subject, role)
			);
			return entity !== undefined;
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				EntityStorageAuthorizationConnector.CLASS_NAME,
				"hasRoleForSubjectFailed",
				{ subject, role },
				err
			);
		}
	}

	/**
	 * Define a parent-child inheritance relationship between two roles.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param role The child role that will inherit permissions from the parent.
	 * @param inheritsFrom The parent role whose permissions are inherited.
	 * @returns Nothing.
	 * @throws GeneralError if the request fails.
	 */
	public async addRoleInheritance(
		modelId: string,
		role: string,
		inheritsFrom: string
	): Promise<void> {
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(role), role);
		this.guardNoSeparator(nameof(inheritsFrom), inheritsFrom);

		const id = this.inheritanceId(modelId, role, inheritsFrom);
		this.guardIdLength(this._authorizationRoleInheritanceEntityStorage, id);
		const inheritsFromNameEntity = this.createRoleName(modelId, inheritsFrom);

		try {
			const inheritance = new AuthorizationRoleInheritance();
			inheritance.id = id;
			inheritance.modelId = modelId;
			inheritance.role = role;
			inheritance.inheritsFrom = inheritsFrom;
			// Write the name first so a failure leaves at worst a stale name, never an unlisted grant.
			await this._authorizationRoleNameEntityStorage.set(inheritsFromNameEntity);
			await this._authorizationRoleInheritanceEntityStorage.set(inheritance);
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				EntityStorageAuthorizationConnector.CLASS_NAME,
				"addRoleInheritanceFailed",
				{ role, inheritsFrom },
				err
			);
		}
	}

	/**
	 * Remove a parent-child inheritance relationship between two roles.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param role The child role.
	 * @param inheritsFrom The parent role to stop inheriting from.
	 * @returns Nothing.
	 * @throws GeneralError if the request fails.
	 */
	public async removeRoleInheritance(
		modelId: string,
		role: string,
		inheritsFrom: string
	): Promise<void> {
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(role), role);
		this.guardNoSeparator(nameof(inheritsFrom), inheritsFrom);

		try {
			await this._authorizationRoleInheritanceEntityStorage.remove(
				this.inheritanceId(modelId, role, inheritsFrom)
			);
			await this.removeRoleNameIfUnreferenced(modelId, role);
			await this.removeRoleNameIfUnreferenced(modelId, inheritsFrom);
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				EntityStorageAuthorizationConnector.CLASS_NAME,
				"removeRoleInheritanceFailed",
				{ role, inheritsFrom },
				err
			);
		}
	}

	/**
	 * Get all roles that a given role directly inherits from.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param role The role to query.
	 * @returns The parent roles.
	 * @throws GeneralError if the query fails.
	 */
	public async getParentRoles(modelId: string, role: string): Promise<string[]> {
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(role), role);

		try {
			return await this.queryAllValues(
				this._authorizationRoleInheritanceEntityStorage,
				{
					logicalOperator: LogicalOperator.And,
					conditions: [
						{ property: "modelId", value: modelId, comparison: ComparisonOperator.Equals },
						{ property: "role", value: role, comparison: ComparisonOperator.Equals }
					]
				},
				"inheritsFrom"
			);
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				EntityStorageAuthorizationConnector.CLASS_NAME,
				"getParentRolesFailed",
				{ role },
				err
			);
		}
	}

	/**
	 * Get all roles that directly inherit from a given role.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param role The role to query.
	 * @returns The child roles.
	 * @throws GeneralError if the query fails.
	 */
	public async getChildRoles(modelId: string, role: string): Promise<string[]> {
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(role), role);

		try {
			return await this.queryAllValues(
				this._authorizationRoleInheritanceEntityStorage,
				{
					logicalOperator: LogicalOperator.And,
					conditions: [
						{ property: "modelId", value: modelId, comparison: ComparisonOperator.Equals },
						{ property: "inheritsFrom", value: role, comparison: ComparisonOperator.Equals }
					]
				},
				"role"
			);
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				EntityStorageAuthorizationConnector.CLASS_NAME,
				"getChildRolesFailed",
				{ role },
				err
			);
		}
	}

	/**
	 * Build the compound primary key for a policy.
	 * @param modelId The model identifier.
	 * @param subject The subject.
	 * @param object The object.
	 * @param action The action.
	 * @returns The compound id string.
	 * @internal
	 */
	private policyId(modelId: string, subject: string, object: string, action: string): string {
		return `${modelId}|${subject}|${object}|${action}`;
	}

	/**
	 * Build the compound primary key for a role assignment.
	 * @param modelId The model identifier.
	 * @param subject The subject.
	 * @param role The role.
	 * @returns The compound id string.
	 * @internal
	 */
	private roleId(modelId: string, subject: string, role: string): string {
		return `${modelId}|${subject}|${role}`;
	}

	/**
	 * Build the compound primary key for a role inheritance relationship.
	 * @param modelId The model identifier.
	 * @param role The child role.
	 * @param inheritsFrom The parent role.
	 * @returns The compound id string.
	 * @internal
	 */
	private inheritanceId(modelId: string, role: string, inheritsFrom: string): string {
		return `${modelId}|${role}|${inheritsFrom}`;
	}

	/**
	 * Build the compound primary key for a role name index entry.
	 * @param modelId The model identifier.
	 * @param name The role name.
	 * @returns The compound id string.
	 * @internal
	 */
	private roleNameId(modelId: string, name: string): string {
		return `${modelId}|${name}`;
	}

	/**
	 * Throw if the given value contains the compound-key separator.
	 * @param fieldName The field name used in the error message.
	 * @param value The value to validate.
	 * @throws GeneralError if the value contains the "|" separator character.
	 * @internal
	 */
	private guardNoSeparator(fieldName: string, value: string): void {
		Guards.stringValue(EntityStorageAuthorizationConnector.CLASS_NAME, fieldName, value);
		if (value.includes("|")) {
			throw new GeneralError(EntityStorageAuthorizationConnector.CLASS_NAME, "containsSeparator", {
				fieldName
			});
		}
	}

	/**
	 * Throw if the compound id exceeds the maximum length declared for the primary key.
	 * @param storage The storage the id will be written to.
	 * @param id The compound id to validate.
	 * @throws GeneralError if the id is too long.
	 * @internal
	 */
	private guardIdLength<T>(storage: IEntityStorageConnector<T>, id: string): void {
		const maxLength = storage.getSchema().properties?.find(p => p.isPrimary)?.maxLength;
		if (Is.integer(maxLength) && id.length > maxLength) {
			throw new GeneralError(EntityStorageAuthorizationConnector.CLASS_NAME, "idTooLong", {
				length: id.length,
				maxLength
			});
		}
	}

	/**
	 * Create a validated role name index entry.
	 * @param modelId The model identifier.
	 * @param name The role name.
	 * @returns The role name entity.
	 * @throws GeneralError if the id is too long.
	 * @internal
	 */
	private createRoleName(modelId: string, name: string): AuthorizationRoleName {
		const roleName = new AuthorizationRoleName();
		roleName.id = this.roleNameId(modelId, name);
		roleName.modelId = modelId;
		roleName.name = name;
		this.guardIdLength(this._authorizationRoleNameEntityStorage, roleName.id);
		return roleName;
	}

	/**
	 * Query every page of matching entities returning the string values of a single property.
	 * @param storage The storage to query.
	 * @param conditions The conditions to match.
	 * @param property The property to project and return.
	 * @returns The property values.
	 * @internal
	 */
	private async queryAllValues<T>(
		storage: IEntityStorageConnector<T>,
		conditions: EntityCondition<T>,
		property: keyof T
	): Promise<string[]> {
		const values: string[] = [];
		let cursor: string | undefined;

		do {
			const result = await storage.query(conditions, undefined, [property], cursor);
			for (const entity of result.entities) {
				const value = entity[property];
				if (Is.stringValue(value)) {
					values.push(value);
				}
			}
			cursor = result.cursor;
		} while (Is.stringValue(cursor));

		return values;
	}

	/**
	 * Join the matching role entries to the policies granting the object and action to their role.
	 * @param storage The storage holding the role entries.
	 * @param roleProperty The property on the role entries holding the role to join on.
	 * @param conditions The conditions to match for the role entries.
	 * @param modelId The model identifier.
	 * @param object The object being accessed.
	 * @param action The action to check.
	 * @returns Whether any role is granted the action, otherwise the roles which were matched.
	 * @internal
	 */
	private async joinRolePolicies<T>(
		storage: IEntityStorageConnector<T>,
		roleProperty: keyof T,
		conditions: EntityCondition<T>,
		modelId: string,
		object: string,
		action: string
	): Promise<{ granted: boolean; roles: string[] }> {
		const roles: string[] = [];
		let cursor: string | undefined;

		do {
			const result = await storage.queryJoin<AuthorizationPolicy>(
				this._authorizationPolicyEntityStorage,
				{
					property: roleProperty,
					joinProperty: "subject",
					conditions,
					properties: [roleProperty],
					joinConditions: {
						logicalOperator: LogicalOperator.And,
						conditions: [
							{ property: "modelId", value: modelId, comparison: ComparisonOperator.Equals },
							{ property: "object", value: object, comparison: ComparisonOperator.Equals },
							{ property: "action", value: action, comparison: ComparisonOperator.Equals }
						]
					},
					joinProperties: ["id"],
					cursor
				}
			);

			for (const entity of result.entities) {
				if (entity.joined.length > 0) {
					return { granted: true, roles };
				}
				const role = entity[roleProperty];
				if (Is.stringValue(role)) {
					roles.push(role);
				}
			}
			cursor = result.cursor;
		} while (Is.stringValue(cursor));

		return { granted: false, roles };
	}

	/**
	 * Remove a role name from the index if it no longer appears in any assignment or inheritance record.
	 * Without transactions a concurrent add can still race the removal, so the references are
	 * re-checked afterwards and the name restored if needed, this narrows but does not close the window.
	 * @param modelId The model identifier.
	 * @param roleName The role name to check.
	 * @internal
	 */
	private async removeRoleNameIfUnreferenced(modelId: string, roleName: string): Promise<void> {
		if (await this.isRoleNameReferenced(modelId, roleName)) {
			return;
		}

		await this._authorizationRoleNameEntityStorage.remove(this.roleNameId(modelId, roleName));

		if (await this.isRoleNameReferenced(modelId, roleName)) {
			await this._authorizationRoleNameEntityStorage.set(this.createRoleName(modelId, roleName));
		}
	}

	/**
	 * Check whether a role name appears in any assignment or inheritance record.
	 * @param modelId The model identifier.
	 * @param roleName The role name to check.
	 * @returns True if the role name is referenced.
	 * @internal
	 */
	private async isRoleNameReferenced(modelId: string, roleName: string): Promise<boolean> {
		const [assignmentResult, inheritanceChildResult, inheritanceParentResult] = await Promise.all([
			this._authorizationRoleAssignmentEntityStorage.query(
				{
					logicalOperator: LogicalOperator.And,
					conditions: [
						{ property: "modelId", value: modelId, comparison: ComparisonOperator.Equals },
						{ property: "role", value: roleName, comparison: ComparisonOperator.Equals }
					]
				},
				undefined,
				["id"],
				undefined,
				1
			),
			this._authorizationRoleInheritanceEntityStorage.query(
				{
					logicalOperator: LogicalOperator.And,
					conditions: [
						{ property: "modelId", value: modelId, comparison: ComparisonOperator.Equals },
						{ property: "role", value: roleName, comparison: ComparisonOperator.Equals }
					]
				},
				undefined,
				["id"],
				undefined,
				1
			),
			this._authorizationRoleInheritanceEntityStorage.query(
				{
					logicalOperator: LogicalOperator.And,
					conditions: [
						{ property: "modelId", value: modelId, comparison: ComparisonOperator.Equals },
						{ property: "inheritsFrom", value: roleName, comparison: ComparisonOperator.Equals }
					]
				},
				undefined,
				["id"],
				undefined,
				1
			)
		]);

		return (
			assignmentResult.entities.length > 0 ||
			inheritanceChildResult.entities.length > 0 ||
			inheritanceParentResult.entities.length > 0
		);
	}
}
