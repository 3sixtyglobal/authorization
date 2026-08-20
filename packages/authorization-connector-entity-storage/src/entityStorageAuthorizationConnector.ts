// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IAuthorizationConnector, IAuthorizationPolicy } from "@twin.org/authorization-models";
import { BaseError, GeneralError, Guards } from "@twin.org/core";
import { ComparisonOperator, SortDirection } from "@twin.org/entity";
import {
	EntityStorageConnectorFactory,
	type IEntityStorageConnector
} from "@twin.org/entity-storage-models";
import { nameof } from "@twin.org/nameof";
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
	 * Check whether a subject is permitted to perform an action on a object.
	 * @param subject The subject requesting access.
	 * @param object The object being accessed.
	 * @param action The action to check.
	 * @returns True if access is granted, false otherwise.
	 * @throws GeneralError if the check request fails.
	 */
	public async check(subject: string, object: string, action: string): Promise<boolean> {
		Guards.stringValue(EntityStorageAuthorizationConnector.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(EntityStorageAuthorizationConnector.CLASS_NAME, nameof(object), object);
		Guards.stringValue(EntityStorageAuthorizationConnector.CLASS_NAME, nameof(action), action);

		try {
			const directPolicy = await this._authorizationPolicyEntityStorage.get(
				this.policyId(subject, object, action)
			);
			if (directPolicy) {
				return true;
			}

			const roleResult = await this._authorizationRoleAssignmentEntityStorage.query(
				{ property: "subject", value: subject, comparison: ComparisonOperator.Equals },
				undefined,
				["role"]
			);

			const queue: string[] = roleResult.entities
				.map(e => e.role)
				.filter((r): r is string => r !== undefined);
			const visited = new Set<string>();

			while (queue.length > 0) {
				const nextRole = queue.shift();
				if (nextRole !== undefined && !visited.has(nextRole)) {
					visited.add(nextRole);

					const rolePolicy = await this._authorizationPolicyEntityStorage.get(
						this.policyId(nextRole, object, action)
					);
					if (rolePolicy) {
						return true;
					}

					const parentResult = await this._authorizationRoleInheritanceEntityStorage.query(
						{ property: "role", value: nextRole, comparison: ComparisonOperator.Equals },
						undefined,
						["parentRole"]
					);
					for (const entry of parentResult.entities) {
						if (entry.parentRole !== undefined && !visited.has(entry.parentRole)) {
							queue.push(entry.parentRole);
						}
					}
				}
			}

			return false;
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
	 * Check whether any of the given subjects are permitted to perform an action on a resource.
	 * @param subjects The subjects to check.
	 * @param object The object being accessed.
	 * @param action The action to check.
	 * @returns True if access is granted for at least one subject, false otherwise.
	 * @throws GeneralError if the check request fails.
	 */
	public async checkAny(
		subjects: string[],
		object: string,
		action: string
	): Promise<(boolean | undefined)[]> {
		Guards.array<string>(
			EntityStorageAuthorizationConnector.CLASS_NAME,
			nameof(subjects),
			subjects
		);
		Guards.stringValue(EntityStorageAuthorizationConnector.CLASS_NAME, nameof(object), object);
		Guards.stringValue(EntityStorageAuthorizationConnector.CLASS_NAME, nameof(action), action);

		try {
			if (subjects.length === 0) {
				return [];
			}
			return await Promise.all(subjects.map(async subject => this.check(subject, object, action)));
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				EntityStorageAuthorizationConnector.CLASS_NAME,
				"checkAnyFailed",
				{ object, action },
				err
			);
		}
	}

	/**
	 * Add a policy rule.
	 * @param policy The policy to add.
	 * @returns Nothing.
	 * @throws GeneralError if the add request fails.
	 */
	public async addPolicy(policy: IAuthorizationPolicy): Promise<void> {
		Guards.object<IAuthorizationPolicy>(
			EntityStorageAuthorizationConnector.CLASS_NAME,
			nameof(policy),
			policy
		);
		Guards.stringValue(
			EntityStorageAuthorizationConnector.CLASS_NAME,
			nameof(policy.subject),
			policy.subject
		);
		Guards.stringValue(
			EntityStorageAuthorizationConnector.CLASS_NAME,
			nameof(policy.object),
			policy.object
		);
		Guards.stringValue(
			EntityStorageAuthorizationConnector.CLASS_NAME,
			nameof(policy.action),
			policy.action
		);

		try {
			const entity = new AuthorizationPolicy();
			entity.id = this.policyId(policy.subject, policy.object, policy.action);
			entity.subject = policy.subject;
			entity.object = policy.object;
			entity.action = policy.action;
			await this._authorizationPolicyEntityStorage.set(entity);
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				EntityStorageAuthorizationConnector.CLASS_NAME,
				"addPolicyFailed",
				{ subject: policy.subject },
				err
			);
		}
	}

	/**
	 * Remove a policy rule.
	 * @param policy The policy to remove.
	 * @returns Nothing.
	 * @throws GeneralError if the remove request fails.
	 */
	public async removePolicy(policy: IAuthorizationPolicy): Promise<void> {
		Guards.object<IAuthorizationPolicy>(
			EntityStorageAuthorizationConnector.CLASS_NAME,
			nameof(policy),
			policy
		);
		Guards.stringValue(
			EntityStorageAuthorizationConnector.CLASS_NAME,
			nameof(policy.subject),
			policy.subject
		);
		Guards.stringValue(
			EntityStorageAuthorizationConnector.CLASS_NAME,
			nameof(policy.object),
			policy.object
		);
		Guards.stringValue(
			EntityStorageAuthorizationConnector.CLASS_NAME,
			nameof(policy.action),
			policy.action
		);

		try {
			await this._authorizationPolicyEntityStorage.remove(
				this.policyId(policy.subject, policy.object, policy.action)
			);
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				EntityStorageAuthorizationConnector.CLASS_NAME,
				"removePolicyFailed",
				{ subject: policy.subject },
				err
			);
		}
	}

	/**
	 * Get all policy rules for a given subject.
	 * @param subject The subject to query.
	 * @returns The matching policies.
	 * @throws GeneralError if the query fails.
	 */
	public async getPoliciesForSubject(subject: string): Promise<IAuthorizationPolicy[]> {
		Guards.stringValue(EntityStorageAuthorizationConnector.CLASS_NAME, nameof(subject), subject);

		try {
			const result = await this.getAllPolicies(subject);
			return result.entities;
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
	 * @param subject Optional subject to filter by.
	 * @param cursor The cursor to request the next chunk of results.
	 * @param limit Limit the number of entities to return.
	 * @returns The matching policies and an optional cursor for the next page.
	 * @throws GeneralError if the query fails.
	 */
	public async getAllPolicies(
		subject?: string,
		cursor?: string,
		limit?: number
	): Promise<{ entities: IAuthorizationPolicy[]; cursor?: string }> {
		try {
			const condition =
				subject !== undefined
					? { property: "subject", value: subject, comparison: ComparisonOperator.Equals }
					: undefined;
			const result = await this._authorizationPolicyEntityStorage.query(
				condition,
				undefined,
				undefined,
				cursor,
				limit
			);
			return {
				entities: (result.entities as AuthorizationPolicy[]).map(e => ({
					subject: e.subject ?? "",
					object: e.object ?? "",
					action: e.action ?? ""
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
	 * @param cursor The cursor to request the next chunk of results.
	 * @param limit Limit the number of roles to return.
	 * @returns The role names and an optional cursor for the next page.
	 * @throws GeneralError if the query fails.
	 */
	public async getAllRoles(
		cursor?: string,
		limit?: number
	): Promise<{ roles: string[]; cursor?: string }> {
		try {
			const result = await this._authorizationRoleNameEntityStorage.query(
				undefined,
				[{ property: "id", sortDirection: SortDirection.Ascending }],
				["id"],
				cursor,
				limit
			);
			return {
				roles: result.entities.map(e => e.id).filter((r): r is string => r !== undefined),
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
	 * Assign a role to a subject.
	 * @param subject The subject to assign the role to.
	 * @param role The role to assign.
	 * @returns Nothing.
	 * @throws GeneralError if the request fails.
	 */
	public async addRoleForSubject(subject: string, role: string): Promise<void> {
		Guards.stringValue(EntityStorageAuthorizationConnector.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(EntityStorageAuthorizationConnector.CLASS_NAME, nameof(role), role);

		try {
			const assignment = new AuthorizationRoleAssignment();
			assignment.id = this.roleId(subject, role);
			assignment.subject = subject;
			assignment.role = role;
			const roleName = new AuthorizationRoleName();
			roleName.id = role;
			await Promise.all([
				this._authorizationRoleAssignmentEntityStorage.set(assignment),
				this._authorizationRoleNameEntityStorage.set(roleName)
			]);
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
	 * @param subject The subject to remove the role from.
	 * @param role The role to remove.
	 * @returns Nothing.
	 * @throws GeneralError if the request fails.
	 */
	public async removeRoleForSubject(subject: string, role: string): Promise<void> {
		Guards.stringValue(EntityStorageAuthorizationConnector.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(EntityStorageAuthorizationConnector.CLASS_NAME, nameof(role), role);

		try {
			await this._authorizationRoleAssignmentEntityStorage.remove(this.roleId(subject, role));
			await this.removeRoleNameIfUnreferenced(role);
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
	 * @param subject The subject to remove all roles from.
	 * @returns Nothing.
	 * @throws GeneralError if the request fails.
	 */
	public async removeAllRolesForSubject(subject: string): Promise<void> {
		Guards.stringValue(EntityStorageAuthorizationConnector.CLASS_NAME, nameof(subject), subject);

		try {
			const result = await this._authorizationRoleAssignmentEntityStorage.query(
				{ property: "subject", value: subject, comparison: ComparisonOperator.Equals },
				undefined,
				["id", "role"]
			);
			const ids = result.entities.map(e => e.id).filter((id): id is string => id !== undefined);
			const roles = result.entities.map(e => e.role).filter((r): r is string => r !== undefined);
			if (ids.length > 0) {
				await this._authorizationRoleAssignmentEntityStorage.removeBatch(ids);
				await Promise.all(roles.map(async r => this.removeRoleNameIfUnreferenced(r)));
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
	 * @param subject The subject to query.
	 * @returns The assigned roles.
	 * @throws GeneralError if the query fails.
	 */
	public async getRolesForSubject(subject: string): Promise<string[]> {
		Guards.stringValue(EntityStorageAuthorizationConnector.CLASS_NAME, nameof(subject), subject);

		try {
			const result = await this._authorizationRoleAssignmentEntityStorage.query(
				{ property: "subject", value: subject, comparison: ComparisonOperator.Equals },
				undefined,
				["role"]
			);
			return result.entities.map(e => e.role).filter((r): r is string => r !== undefined);
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
	 * @param role The role to query.
	 * @returns The subjects with the given role.
	 * @throws GeneralError if the query fails.
	 */
	public async getSubjectsForRole(role: string): Promise<string[]> {
		Guards.stringValue(EntityStorageAuthorizationConnector.CLASS_NAME, nameof(role), role);

		try {
			const result = await this._authorizationRoleAssignmentEntityStorage.query(
				{ property: "role", value: role, comparison: ComparisonOperator.Equals },
				undefined,
				["subject"]
			);
			return result.entities.map(e => e.subject).filter((s): s is string => s !== undefined);
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
	 * @param subject The subject to check.
	 * @param role The role to check for.
	 * @returns True if the subject has the role.
	 * @throws GeneralError if the request fails.
	 */
	public async hasRoleForSubject(subject: string, role: string): Promise<boolean> {
		Guards.stringValue(EntityStorageAuthorizationConnector.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(EntityStorageAuthorizationConnector.CLASS_NAME, nameof(role), role);

		try {
			const entity = await this._authorizationRoleAssignmentEntityStorage.get(
				this.roleId(subject, role)
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
	 * @param role The child role that will inherit permissions from the parent.
	 * @param parentRole The parent role whose permissions are inherited.
	 * @returns Nothing.
	 * @throws GeneralError if the request fails.
	 */
	public async addRoleInheritance(role: string, parentRole: string): Promise<void> {
		Guards.stringValue(EntityStorageAuthorizationConnector.CLASS_NAME, nameof(role), role);
		Guards.stringValue(
			EntityStorageAuthorizationConnector.CLASS_NAME,
			nameof(parentRole),
			parentRole
		);

		try {
			const inheritance = new AuthorizationRoleInheritance();
			inheritance.id = this.inheritanceId(role, parentRole);
			inheritance.role = role;
			inheritance.parentRole = parentRole;
			const roleNameEntity = new AuthorizationRoleName();
			roleNameEntity.id = role;
			const parentRoleNameEntity = new AuthorizationRoleName();
			parentRoleNameEntity.id = parentRole;
			await Promise.all([
				this._authorizationRoleInheritanceEntityStorage.set(inheritance),
				this._authorizationRoleNameEntityStorage.set(roleNameEntity),
				this._authorizationRoleNameEntityStorage.set(parentRoleNameEntity)
			]);
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				EntityStorageAuthorizationConnector.CLASS_NAME,
				"addRoleInheritanceFailed",
				{ role, parentRole },
				err
			);
		}
	}

	/**
	 * Remove a parent-child inheritance relationship between two roles.
	 * @param role The child role.
	 * @param parentRole The parent role to stop inheriting from.
	 * @returns Nothing.
	 * @throws GeneralError if the request fails.
	 */
	public async removeRoleInheritance(role: string, parentRole: string): Promise<void> {
		Guards.stringValue(EntityStorageAuthorizationConnector.CLASS_NAME, nameof(role), role);
		Guards.stringValue(
			EntityStorageAuthorizationConnector.CLASS_NAME,
			nameof(parentRole),
			parentRole
		);

		try {
			await this._authorizationRoleInheritanceEntityStorage.remove(
				this.inheritanceId(role, parentRole)
			);
			await Promise.all([
				this.removeRoleNameIfUnreferenced(role),
				this.removeRoleNameIfUnreferenced(parentRole)
			]);
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				EntityStorageAuthorizationConnector.CLASS_NAME,
				"removeRoleInheritanceFailed",
				{ role, parentRole },
				err
			);
		}
	}

	/**
	 * Get all roles that a given role directly inherits from.
	 * @param role The role to query.
	 * @returns The parent roles.
	 * @throws GeneralError if the query fails.
	 */
	public async getParentRoles(role: string): Promise<string[]> {
		Guards.stringValue(EntityStorageAuthorizationConnector.CLASS_NAME, nameof(role), role);

		try {
			const result = await this._authorizationRoleInheritanceEntityStorage.query(
				{ property: "role", value: role, comparison: ComparisonOperator.Equals },
				undefined,
				["parentRole"]
			);
			return result.entities.map(e => e.parentRole).filter((r): r is string => r !== undefined);
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
	 * @param role The role to query.
	 * @returns The child roles.
	 * @throws GeneralError if the query fails.
	 */
	public async getChildRoles(role: string): Promise<string[]> {
		Guards.stringValue(EntityStorageAuthorizationConnector.CLASS_NAME, nameof(role), role);

		try {
			const result = await this._authorizationRoleInheritanceEntityStorage.query(
				{ property: "parentRole", value: role, comparison: ComparisonOperator.Equals },
				undefined,
				["role"]
			);
			return result.entities.map(e => e.role).filter((r): r is string => r !== undefined);
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
	 * @param subject The subject.
	 * @param object The object.
	 * @param action The action.
	 * @returns The compound id string.
	 * @internal
	 */
	private policyId(subject: string, object: string, action: string): string {
		return `${subject}|${object}|${action}`;
	}

	/**
	 * Build the compound primary key for a role assignment.
	 * @param subject The subject.
	 * @param role The role.
	 * @returns The compound id string.
	 * @internal
	 */
	private roleId(subject: string, role: string): string {
		return `${subject}|${role}`;
	}

	/**
	 * Build the compound primary key for a role inheritance relationship.
	 * @param role The child role.
	 * @param parentRole The parent role.
	 * @returns The compound id string.
	 * @internal
	 */
	private inheritanceId(role: string, parentRole: string): string {
		return `${role}|${parentRole}`;
	}

	/**
	 * Remove a role name from the index if it no longer appears in any assignment or inheritance record.
	 * @param roleName The role name to check.
	 * @internal
	 */
	private async removeRoleNameIfUnreferenced(roleName: string): Promise<void> {
		const [assignmentResult, inheritanceChildResult, inheritanceParentResult] = await Promise.all([
			this._authorizationRoleAssignmentEntityStorage.query(
				{ property: "role", value: roleName, comparison: ComparisonOperator.Equals },
				undefined,
				["id"],
				undefined,
				1
			),
			this._authorizationRoleInheritanceEntityStorage.query(
				{ property: "role", value: roleName, comparison: ComparisonOperator.Equals },
				undefined,
				["id"],
				undefined,
				1
			),
			this._authorizationRoleInheritanceEntityStorage.query(
				{ property: "parentRole", value: roleName, comparison: ComparisonOperator.Equals },
				undefined,
				["id"],
				undefined,
				1
			)
		]);

		if (
			assignmentResult.entities.length === 0 &&
			inheritanceChildResult.entities.length === 0 &&
			inheritanceParentResult.entities.length === 0
		) {
			await this._authorizationRoleNameEntityStorage.remove(roleName);
		}
	}
}
