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
import { ContextIdKeys, ContextIdStore, type IContextIds } from "@twin.org/context";
import { ComponentFactory, GeneralError, Guards, Is, LfuCache, SharedStore } from "@twin.org/core";
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
	 * The model identifier to use when migrating old authorization data.
	 * @internal
	 */
	private readonly _migrationModelId: string;

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
	 * @throws GeneralError If no authorization connectors are registered.
	 */
	constructor(options?: IAuthorizationServiceConstructorOptions) {
		const names = AuthorizationConnectorFactory.names();
		if (names.length === 0) {
			throw new GeneralError(AuthorizationService.CLASS_NAME, "noConnectors");
		}

		this._telemetryComponent = ComponentFactory.getIfExists<ITelemetryComponent>(
			options?.telemetryComponentType
		);

		this._defaultNamespace = options?.config?.defaultNamespace ?? names[0];
		this._migrationModelId = options?.config?.migrationModelId ?? "rest";

		this._checkCache = new LfuCache<boolean>({
			capacity: options?.config?.checkCacheCapacity,
			ttiMs: options?.config?.checkCacheTtiMs ?? 60000
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
	 * Start the service, applying default rules and registering telemetry metrics.
	 */
	public async start(): Promise<void> {
		// If a migration of the roles from the old authenticated users has just happened
		// the old roles will be stored in the SharedStore, if they exist then we need
		// to populate them in the authorization service.
		const migratedRoles =
			SharedStore.get<{ identity: string; roles: string[]; contextIds: IContextIds | undefined }[]>(
				"migrationUserRoles"
			) ?? [];
		if (Is.arrayValue(migratedRoles)) {
			for (const entry of migratedRoles) {
				await ContextIdStore.run(entry.contextIds ?? {}, async () => {
					for (const role of entry.roles) {
						await this.addRoleForSubject(this._migrationModelId, entry.identity, role);
					}
				});
			}
			SharedStore.remove("migrationUserRoles");
		}

		if (Is.undefined(this._telemetryComponent)) {
			return;
		}
		await MetricHelper.createMetrics(this._telemetryComponent, AUTHORIZATION_METRICS);
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
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(object), object);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(action), action);

		try {
			const connector = this.getConnector();
			const key = await this.buildCacheKey(modelId, subject, object, action);
			return await this._checkCache.getOrSet(key, async () =>
				connector.check(modelId, subject, object, action)
			);
		} catch (error) {
			throw new GeneralError(AuthorizationService.CLASS_NAME, "checkFailed", undefined, error);
		}
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
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(object), object);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(action), action);

		try {
			const connector = this.getConnector();
			await connector.addPolicy(modelId, subject, object, action);
			await this.deleteExactCacheKey(modelId, subject, object, action);

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
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(object), object);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(action), action);

		try {
			const connector = this.getConnector();
			await connector.removePolicy(modelId, subject, object, action);
			await this.deleteExactCacheKey(modelId, subject, object, action);

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
	): Promise<{ entities: IAuthorizationPolicy[]; cursor?: string }> {
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(subject), subject);

		try {
			const connector = this.getConnector();
			return await connector.getPoliciesForSubject(modelId, subject, cursor, limit);
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
	): Promise<{ entities: IAuthorizationPolicy[]; cursor?: string }> {
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(modelId), modelId);

		try {
			const connector = this.getConnector();
			return await connector.getAllPolicies(modelId, subject, cursor, limit);
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
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(modelId), modelId);

		try {
			const connector = this.getConnector();
			return await connector.getAllRoles(modelId, cursor, limit);
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
	 * Check whether each of the given role names exists in the system.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param roles The role names to check.
	 * @returns An array of booleans in the same order as the input.
	 */
	public async hasRoles(modelId: string, roles: string[]): Promise<boolean[]> {
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(modelId), modelId);
		Guards.array<string>(AuthorizationService.CLASS_NAME, nameof(roles), roles);

		try {
			const connector = this.getConnector();
			return await connector.hasRoles(modelId, roles);
		} catch (error) {
			throw new GeneralError(AuthorizationService.CLASS_NAME, "hasRolesFailed", undefined, error);
		}
	}

	/**
	 * Assign a role to a subject.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject to assign the role to.
	 * @param role The role to assign.
	 * @returns Nothing.
	 */
	public async addRoleForSubject(modelId: string, subject: string, role: string): Promise<void> {
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(role), role);

		try {
			const connector = this.getConnector();
			await connector.addRoleForSubject(modelId, subject, role);
			await this.invalidateCacheByPrefix(modelId, subject);

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
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject to remove the role from.
	 * @param role The role to remove.
	 * @returns Nothing.
	 */
	public async removeRoleForSubject(modelId: string, subject: string, role: string): Promise<void> {
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(role), role);

		try {
			const connector = this.getConnector();
			await connector.removeRoleForSubject(modelId, subject, role);
			await this.invalidateCacheByPrefix(modelId, subject);

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
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject to remove all roles from.
	 * @returns Nothing.
	 */
	public async removeAllRolesForSubject(modelId: string, subject: string): Promise<void> {
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(subject), subject);

		try {
			const connector = this.getConnector();
			await connector.removeAllRolesForSubject(modelId, subject);
			await this.invalidateCacheByPrefix(modelId, subject);

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
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject to query.
	 * @returns The assigned roles.
	 */
	public async getRolesForSubject(modelId: string, subject: string): Promise<string[]> {
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(subject), subject);

		try {
			const connector = this.getConnector();
			return await connector.getRolesForSubject(modelId, subject);
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
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param role The role to query.
	 * @returns The subjects with the given role.
	 */
	public async getSubjectsForRole(modelId: string, role: string): Promise<string[]> {
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(role), role);

		try {
			const connector = this.getConnector();
			return await connector.getSubjectsForRole(modelId, role);
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
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param subject The subject to check.
	 * @param role The role to check for.
	 * @returns True if the subject has the role.
	 */
	public async hasRoleForSubject(modelId: string, subject: string, role: string): Promise<boolean> {
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(role), role);

		try {
			const connector = this.getConnector();
			return await connector.hasRoleForSubject(modelId, subject, role);
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
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(role), role);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(inheritsFrom), inheritsFrom);

		try {
			const connector = this.getConnector();
			await connector.addRoleInheritance(modelId, role, inheritsFrom);
			await this.invalidateCacheByPrefix(modelId, role);

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
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(role), role);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(inheritsFrom), inheritsFrom);

		try {
			const connector = this.getConnector();
			await connector.removeRoleInheritance(modelId, role, inheritsFrom);
			await this.invalidateCacheByPrefix(modelId, role);

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
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param role The role to query.
	 * @returns The parent roles.
	 */
	public async getParentRoles(modelId: string, role: string): Promise<string[]> {
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(role), role);

		try {
			const connector = this.getConnector();
			return await connector.getParentRoles(modelId, role);
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
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param role The role to query.
	 * @returns The child roles.
	 */
	public async getChildRoles(modelId: string, role: string): Promise<string[]> {
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(modelId), modelId);
		Guards.stringValue(AuthorizationService.CLASS_NAME, nameof(role), role);

		try {
			const connector = this.getConnector();
			return await connector.getChildRoles(modelId, role);
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
	 * Build a tenant-and-model-aware cache key.
	 * @param modelId The model identifier.
	 * @param subject The subject.
	 * @param object The object.
	 * @param action The action.
	 * @returns The cache key string.
	 * @internal
	 */
	private async buildCacheKey(
		modelId: string,
		subject: string,
		object: string,
		action: string
	): Promise<string> {
		const contextIds = await ContextIdStore.getContextIds();
		const tenantId = contextIds?.[ContextIdKeys.Tenant] ?? "";
		return `${tenantId}:${modelId}:${subject}:${object}:${action}`;
	}

	/**
	 * Delete the exact cache entry for the given model, subject, object, and action.
	 * @param modelId The model identifier.
	 * @param subject The subject.
	 * @param object The object.
	 * @param action The action.
	 * @internal
	 */
	private async deleteExactCacheKey(
		modelId: string,
		subject: string,
		object: string,
		action: string
	): Promise<void> {
		const key = await this.buildCacheKey(modelId, subject, object, action);
		this._checkCache.delete(key);
	}

	/**
	 * Evict all cached check() results whose key starts with the given part under the current tenant and model.
	 * @param modelId The model identifier.
	 * @param part The subject or role name to use as the key prefix segment.
	 * @internal
	 */
	private async invalidateCacheByPrefix(modelId: string, part: string): Promise<void> {
		const contextIds = await ContextIdStore.getContextIds();
		const tenantId = contextIds?.[ContextIdKeys.Tenant] ?? "";
		const prefix = `${tenantId}:${modelId}:${part}:`;
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
