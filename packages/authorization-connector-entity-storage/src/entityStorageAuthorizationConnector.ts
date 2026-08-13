// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IAuthorizationConnector, IAuthorizationPolicy } from "@twin.org/authorization-models";
import { BaseError, GeneralError, Guards } from "@twin.org/core";
import { ComparisonOperator } from "@twin.org/entity";
import {
	EntityStorageConnectorFactory,
	type IEntityStorageConnector
} from "@twin.org/entity-storage-models";
import { nameof } from "@twin.org/nameof";
import { AuthorizationPolicy } from "./entities/authorizationPolicy.js";
import { AuthorizationRoleAssignment } from "./entities/authorizationRoleAssignment.js";
import { AuthorizationRoleInheritance } from "./entities/authorizationRoleInheritance.js";
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
	private readonly _authorizationRoleEntityStorage: IEntityStorageConnector<AuthorizationRoleAssignment>;

	/**
	 * The entity storage for authorization role inheritance relationships.
	 * @internal
	 */
	private readonly _authorizationRoleInheritanceEntityStorage: IEntityStorageConnector<AuthorizationRoleInheritance>;

	/**
	 * Create a new instance of EntityStorageAuthorizationConnector.
	 * @param options The dependencies for the class.
	 */
	constructor(options?: IEntityStorageAuthorizationConnectorConstructorOptions) {
		this._authorizationPolicyEntityStorage = EntityStorageConnectorFactory.get(
			options?.authorizationPolicyEntityStorageType ?? "authorization-policy"
		);
		this._authorizationRoleEntityStorage = EntityStorageConnectorFactory.get(
			options?.authorizationRoleEntityStorageType ?? "authorization-role"
		);
		this._authorizationRoleInheritanceEntityStorage = EntityStorageConnectorFactory.get(
			options?.authorizationRoleInheritanceEntityStorageType ?? "authorization-role-inheritance"
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

			const roleResult = await this._authorizationRoleEntityStorage.query(
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
			const roleSet = new Set<string>();

			let assignmentCursor: string | undefined;
			do {
				const assignmentResult = await this._authorizationRoleEntityStorage.query(
					undefined,
					undefined,
					["role"],
					assignmentCursor,
					1000
				);
				for (const e of assignmentResult.entities) {
					if (e.role !== undefined) {
						roleSet.add(e.role);
					}
				}
				assignmentCursor = assignmentResult.cursor;
			} while (assignmentCursor !== undefined);

			let inheritanceCursor: string | undefined;
			do {
				const inheritanceResult = await this._authorizationRoleInheritanceEntityStorage.query(
					undefined,
					undefined,
					["role", "parentRole"],
					inheritanceCursor,
					1000
				);
				for (const e of inheritanceResult.entities) {
					if (e.role !== undefined) {
						roleSet.add(e.role);
					}
					if (e.parentRole !== undefined) {
						roleSet.add(e.parentRole);
					}
				}
				inheritanceCursor = inheritanceResult.cursor;
			} while (inheritanceCursor !== undefined);

			const allRoles = Array.from(roleSet).sort();

			const offset = cursor !== undefined ? parseInt(cursor, 10) : 0;
			const pageSize = limit ?? allRoles.length;
			const pageRoles = allRoles.slice(offset, offset + pageSize);
			const nextOffset = offset + pageSize;

			return {
				roles: pageRoles,
				cursor: nextOffset < allRoles.length ? String(nextOffset) : undefined
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
			const entity = new AuthorizationRoleAssignment();
			entity.id = this.roleId(subject, role);
			entity.subject = subject;
			entity.role = role;
			await this._authorizationRoleEntityStorage.set(entity);
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
			await this._authorizationRoleEntityStorage.remove(this.roleId(subject, role));
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
			const result = await this._authorizationRoleEntityStorage.query(
				{ property: "subject", value: subject, comparison: ComparisonOperator.Equals },
				undefined,
				["id"]
			);
			const ids = result.entities.map(e => e.id).filter((id): id is string => id !== undefined);
			if (ids.length > 0) {
				await this._authorizationRoleEntityStorage.removeBatch(ids);
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
			const result = await this._authorizationRoleEntityStorage.query(
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
			const result = await this._authorizationRoleEntityStorage.query(
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
			const entity = await this._authorizationRoleEntityStorage.get(this.roleId(subject, role));
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
			const entity = new AuthorizationRoleInheritance();
			entity.id = this.inheritanceId(role, parentRole);
			entity.role = role;
			entity.parentRole = parentRole;
			await this._authorizationRoleInheritanceEntityStorage.set(entity);
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
}
