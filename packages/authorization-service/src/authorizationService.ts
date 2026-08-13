// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import {
	AUTHORIZATION_METRIC_IDS,
	AUTHORIZATION_METRICS,
	AuthorizationConnectorFactory,
	type IAuthorizationComponent,
	type IAuthorizationConnector,
	type IAuthorizationPolicy
} from "@twin.org/authorization-models";
import { ContextIdKeys, ContextIdStore } from "@twin.org/context";
import { ComponentFactory, GeneralError, Guards, Is, LfuCache } from "@twin.org/core";
import { nameof } from "@twin.org/nameof";
import { MetricHelper, type ITelemetryComponent } from "@twin.org/telemetry-models";
import type { IAuthorizationServiceConstructorOptions } from "./models/IAuthorizationServiceConstructorOptions.js";

/**
 * A service that implements the IAuthorizationComponent interface for handling authorization logic.
 */
export class AuthorizationService implements IAuthorizationComponent {
	/**
	 * Runtime name for the class.
	 */
	public static readonly CLASS_NAME: string = nameof<AuthorizationService>();

	/**
	 * The default namespace for the connector to use.
	 * @internal
	 */
	private readonly _defaultNamespace: string;

	/**
	 * The optional telemetry component for recording metrics.
	 * @internal
	 */
	private readonly _telemetryComponent?: ITelemetryComponent;

	/**
	 * LFU cache for check() results, keyed by tenant-aware composite key.
	 * @internal
	 */
	private readonly _checkCache: LfuCache<boolean>;

	/**
	 * Create a new instance of AuthorizationService.
	 * @param options The constructor options.
	 * @throws {GeneralError} If no authorization connectors are registered.
	 */
	constructor(options?: IAuthorizationServiceConstructorOptions) {
		const names = AuthorizationConnectorFactory.names();
		if (names.length === 0) {
			throw new GeneralError(AuthorizationService.CLASS_NAME, "noConnectors");
		}

		this._defaultNamespace = options?.config?.defaultNamespace ?? names[0];
		this._telemetryComponent = ComponentFactory.getIfExists<ITelemetryComponent>(
			options?.telemetryComponentType
		);
		this._checkCache = new LfuCache<boolean>({
			capacity: options?.config?.checkCacheCapacity,
			ttiMs: options?.config?.checkCacheTtiMs
		});
	}

	/**
	 * Returns the class name of the component.
	 * @returns The class name of the component.
	 */
	public className(): string {
		return AuthorizationService.CLASS_NAME;
	}

	/**
	 * Registers the authorization metrics with the telemetry component.
	 */
	public async start(): Promise<void> {
		if (Is.undefined(this._telemetryComponent)) {
			return;
		}
		await MetricHelper.createMetrics(this._telemetryComponent, AUTHORIZATION_METRICS);
	}

	/**
	 * Check whether a subject is permitted to perform an action on a resource.
	 * @param subject The subject requesting access.
	 * @param object The object being accessed.
	 * @param action The action to check.
	 * @returns True if access is granted, false otherwise.
	 */
	public async check(subject: string, object: string, action: string): Promise<boolean> {
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(object), object);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(action), action);

		try {
			const connector = this.getConnector();
			const key = await this.checkCacheKey(subject, object, action);
			return await this._checkCache.getOrSet(key, async () =>
				connector.check(subject, object, action)
			);
		} catch (error) {
			throw new GeneralError(AuthorizationService.CLASS_NAME, "checkFailed", undefined, error);
		}
	}

	/**
	 * Add a policy rule.
	 * @param policy The policy to add.
	 * @returns Nothing.
	 */
	public async addPolicy(policy: IAuthorizationPolicy): Promise<void> {
		Guards.object(AuthorizationService.CLASS_NAME, nameof(policy), policy);

		try {
			const connector = this.getConnector();
			await connector.addPolicy(policy);
			await this.deleteExactCacheKey(policy.subject, policy.object, policy.action);

			await MetricHelper.metricIncrement(
				this._telemetryComponent,
				AUTHORIZATION_METRIC_IDS.PoliciesAdded
			);
		} catch (error) {
			throw new GeneralError(AuthorizationService.CLASS_NAME, "addPolicyFailed", undefined, error);
		}
	}

	/**
	 * Remove a policy rule.
	 * @param policy The policy to remove.
	 * @returns Nothing.
	 */
	public async removePolicy(policy: IAuthorizationPolicy): Promise<void> {
		Guards.object(AuthorizationService.CLASS_NAME, nameof(policy), policy);

		try {
			const connector = this.getConnector();
			await connector.removePolicy(policy);
			await this.deleteExactCacheKey(policy.subject, policy.object, policy.action);

			await MetricHelper.metricIncrement(
				this._telemetryComponent,
				AUTHORIZATION_METRIC_IDS.PoliciesRemoved
			);
		} catch (error) {
			throw new GeneralError(
				AuthorizationService.CLASS_NAME,
				"removePolicyFailed",
				undefined,
				error
			);
		}
	}

	/**
	 * Get all policy rules for a given subject.
	 * @param subject The subject to query.
	 * @returns The matching policies.
	 */
	public async getPoliciesForSubject(subject: string): Promise<IAuthorizationPolicy[]> {
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(subject), subject);

		try {
			const connector = this.getConnector();
			const result = await connector.getPoliciesForSubject(subject);
			return result;
		} catch (error) {
			throw new GeneralError(
				AuthorizationService.CLASS_NAME,
				"getPoliciesForSubjectFailed",
				undefined,
				error
			);
		}
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
		try {
			const connector = this.getConnector();
			return await connector.getAllPolicies(subject, cursor, limit);
		} catch (error) {
			throw new GeneralError(
				AuthorizationService.CLASS_NAME,
				"getAllPoliciesFailed",
				undefined,
				error
			);
		}
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
		try {
			const connector = this.getConnector();
			return await connector.getAllRoles(cursor, limit);
		} catch (error) {
			throw new GeneralError(
				AuthorizationService.CLASS_NAME,
				"getAllRolesFailed",
				undefined,
				error
			);
		}
	}

	/**
	 * Assign a role to a subject.
	 * @param subject The subject to assign the role to.
	 * @param role The role to assign.
	 * @returns Nothing.
	 */
	public async addRoleForSubject(subject: string, role: string): Promise<void> {
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(role), role);

		try {
			const connector = this.getConnector();
			await connector.addRoleForSubject(subject, role);
			await this.invalidateCacheByPrefix(subject);

			await MetricHelper.metricIncrement(
				this._telemetryComponent,
				AUTHORIZATION_METRIC_IDS.RolesAdded
			);
		} catch (error) {
			throw new GeneralError(
				AuthorizationService.CLASS_NAME,
				"addRoleForSubjectFailed",
				undefined,
				error
			);
		}
	}

	/**
	 * Remove a role from a subject.
	 * @param subject The subject to remove the role from.
	 * @param role The role to remove.
	 * @returns Nothing.
	 */
	public async removeRoleForSubject(subject: string, role: string): Promise<void> {
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(role), role);

		try {
			const connector = this.getConnector();
			await connector.removeRoleForSubject(subject, role);
			await this.invalidateCacheByPrefix(subject);

			await MetricHelper.metricIncrement(
				this._telemetryComponent,
				AUTHORIZATION_METRIC_IDS.RolesRemoved
			);
		} catch (error) {
			throw new GeneralError(
				AuthorizationService.CLASS_NAME,
				"removeRoleForSubjectFailed",
				undefined,
				error
			);
		}
	}

	/**
	 * Remove all roles from a subject.
	 * @param subject The subject to remove all roles from.
	 * @returns Nothing.
	 */
	public async removeAllRolesForSubject(subject: string): Promise<void> {
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(subject), subject);

		try {
			const connector = this.getConnector();
			await connector.removeAllRolesForSubject(subject);
			await this.invalidateCacheByPrefix(subject);

			await MetricHelper.metricIncrement(
				this._telemetryComponent,
				AUTHORIZATION_METRIC_IDS.RolesRemoved
			);
		} catch (error) {
			throw new GeneralError(
				AuthorizationService.CLASS_NAME,
				"removeAllRolesForSubjectFailed",
				undefined,
				error
			);
		}
	}

	/**
	 * Get all roles assigned to a subject.
	 * @param subject The subject to query.
	 * @returns The assigned roles.
	 */
	public async getRolesForSubject(subject: string): Promise<string[]> {
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(subject), subject);

		try {
			const connector = this.getConnector();
			const result = await connector.getRolesForSubject(subject);
			return result;
		} catch (error) {
			throw new GeneralError(
				AuthorizationService.CLASS_NAME,
				"getRolesForSubjectFailed",
				undefined,
				error
			);
		}
	}

	/**
	 * Get all subjects assigned to a given role.
	 * @param role The role to query.
	 * @returns The subjects with the given role.
	 */
	public async getSubjectsForRole(role: string): Promise<string[]> {
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(role), role);

		try {
			const connector = this.getConnector();
			const result = await connector.getSubjectsForRole(role);
			return result;
		} catch (error) {
			throw new GeneralError(
				AuthorizationService.CLASS_NAME,
				"getSubjectsForRoleFailed",
				undefined,
				error
			);
		}
	}

	/**
	 * Check whether a subject has a specific role.
	 * @param subject The subject to check.
	 * @param role The role to check for.
	 * @returns True if the subject has the role.
	 */
	public async hasRoleForSubject(subject: string, role: string): Promise<boolean> {
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(role), role);

		try {
			const connector = this.getConnector();
			const result = await connector.hasRoleForSubject(subject, role);
			return result;
		} catch (error) {
			throw new GeneralError(
				AuthorizationService.CLASS_NAME,
				"hasRoleForSubjectFailed",
				undefined,
				error
			);
		}
	}

	/**
	 * Define a parent-child inheritance relationship between two roles.
	 * @param role The child role that will inherit permissions from the parent.
	 * @param parentRole The parent role whose permissions are inherited.
	 * @returns Nothing.
	 */
	public async addRoleInheritance(role: string, parentRole: string): Promise<void> {
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(role), role);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(parentRole), parentRole);

		try {
			const connector = this.getConnector();
			await connector.addRoleInheritance(role, parentRole);
			await this.invalidateCacheByPrefix(role);

			await MetricHelper.metricIncrement(
				this._telemetryComponent,
				AUTHORIZATION_METRIC_IDS.RoleInheritancesAdded
			);
		} catch (error) {
			throw new GeneralError(
				AuthorizationService.CLASS_NAME,
				"addRoleInheritanceFailed",
				undefined,
				error
			);
		}
	}

	/**
	 * Remove a parent-child inheritance relationship between two roles.
	 * @param role The child role.
	 * @param parentRole The parent role to stop inheriting from.
	 * @returns Nothing.
	 */
	public async removeRoleInheritance(role: string, parentRole: string): Promise<void> {
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(role), role);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(parentRole), parentRole);

		try {
			const connector = this.getConnector();
			await connector.removeRoleInheritance(role, parentRole);
			await this.invalidateCacheByPrefix(role);

			await MetricHelper.metricIncrement(
				this._telemetryComponent,
				AUTHORIZATION_METRIC_IDS.RoleInheritancesRemoved
			);
		} catch (error) {
			throw new GeneralError(
				AuthorizationService.CLASS_NAME,
				"removeRoleInheritanceFailed",
				undefined,
				error
			);
		}
	}

	/**
	 * Get all roles that a given role directly inherits from.
	 * @param role The role to query.
	 * @returns The parent roles.
	 */
	public async getParentRoles(role: string): Promise<string[]> {
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(role), role);

		try {
			const connector = this.getConnector();
			const result = await connector.getParentRoles(role);
			return result;
		} catch (error) {
			throw new GeneralError(
				AuthorizationService.CLASS_NAME,
				"getParentRolesFailed",
				undefined,
				error
			);
		}
	}

	/**
	 * Get all roles that directly inherit from a given role.
	 * @param role The role to query.
	 * @returns The child roles.
	 */
	public async getChildRoles(role: string): Promise<string[]> {
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(role), role);

		try {
			const connector = this.getConnector();
			const result = await connector.getChildRoles(role);
			return result;
		} catch (error) {
			throw new GeneralError(
				AuthorizationService.CLASS_NAME,
				"getChildRolesFailed",
				undefined,
				error
			);
		}
	}

	/**
	 * Build a tenant-aware cache key for a check() call.
	 * @param subject The subject.
	 * @param object The object.
	 * @param action The action.
	 * @returns The cache key string.
	 * @internal
	 */
	private async checkCacheKey(subject: string, object: string, action: string): Promise<string> {
		const contextIds = await ContextIdStore.getContextIds();
		const tenantId = contextIds?.[ContextIdKeys.Tenant] ?? "";
		return `${tenantId}:${subject}:${object}:${action}`;
	}

	/**
	 * Delete the exact cache entry for the given subject, object, and action.
	 * @param subject The subject.
	 * @param object The object.
	 * @param action The action.
	 * @internal
	 */
	private async deleteExactCacheKey(
		subject: string,
		object: string,
		action: string
	): Promise<void> {
		const key = await this.checkCacheKey(subject, object, action);
		this._checkCache.delete(key);
	}

	/**
	 * Evict all cached check() results whose key starts with the given part under the current tenant.
	 * @param part The subject or role name to use as the key prefix segment.
	 * @internal
	 */
	private async invalidateCacheByPrefix(part: string): Promise<void> {
		const contextIds = await ContextIdStore.getContextIds();
		const tenantId = contextIds?.[ContextIdKeys.Tenant] ?? "";
		const prefix = `${tenantId}:${part}:`;
		for (const key of this._checkCache.keys()) {
			if (key.startsWith(prefix)) {
				this._checkCache.delete(key);
			}
		}
	}

	/**
	 * Get the connector for the default namespace.
	 * @returns The connector.
	 * @internal
	 */
	private getConnector(): IAuthorizationConnector {
		return AuthorizationConnectorFactory.get<IAuthorizationConnector>(this._defaultNamespace);
	}
}
