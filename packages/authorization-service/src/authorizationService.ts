// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import {
	AUTHORIZATION_METRIC_IDS,
	AUTHORIZATION_METRICS,
	AuthorizationConnectorFactory,
	type IAuthorizationComponent,
	type IAuthorizationConnector,
	type IAuthorizationModel,
	type IAuthorizationPolicy
} from "@twin.org/authorization-models";
import { ContextIdKeys, ContextIdStore } from "@twin.org/context";
import {
	ComponentFactory,
	GeneralError,
	Guards,
	Is,
	LfuCache,
	UnauthorizedError
} from "@twin.org/core";
import type { ILoggingComponent } from "@twin.org/logging-models";
import { nameof } from "@twin.org/nameof";
import { MetricHelper, type ITelemetryComponent } from "@twin.org/telemetry-models";
import type { IAuthorizationServiceConstructorOptions } from "./models/IAuthorizationServiceConstructorOptions.js";

/**
 * The check cache tenant scope used when no tenant context id is set.
 */
const ROOT_TENANT = "root";

/**
 * The check cache organization scope used when no organization context id is set.
 */
const GLOBAL_ORGANIZATION = "*";

/**
 * A service that implements the IAuthorizationComponent interface for handling authorization logic.
 */
export class AuthorizationService implements IAuthorizationComponent {
	/**
	 * Runtime name for the class.
	 */
	public static readonly CLASS_NAME: string = nameof<AuthorizationService>();

	/**
	 * The model identifier that is reserved for system-only use.
	 */
	public static readonly DEFAULT_AUTHORIZATION_MODEL_ID: string = "system";

	/**
	 * The role that bypasses all escalation guards when held by the caller.
	 */
	public static readonly DEFAULT_ESCALATED_PRIVILEGE_ROLE: string = "global-admin";

	/**
	 * The default namespace for the connector to use.
	 * @internal
	 */
	private readonly _defaultNamespace: string;

	/**
	 * The optional logging component.
	 * @internal
	 */
	private readonly _loggingComponent?: ILoggingComponent;

	/**
	 * The optional telemetry component for recording metrics.
	 * @internal
	 */
	private readonly _telemetryComponent?: ITelemetryComponent;

	/**
	 * The model identifier reserved for system-only builds.
	 * @internal
	 */
	private readonly _authorizationModelId: string | undefined;

	/**
	 * The role that grants the holder unrestricted access to all mutation operations.
	 * @internal
	 */
	private readonly _escalatedPrivilegeRole: string;

	/**
	 * LFU cache config used when creating per-model check() caches.
	 * @internal
	 */
	private readonly _checkCacheConfig: { capacity?: number; ttiMs: number };

	/**
	 * Per-tenant, per-organization, per-model LFU caches for check() results.
	 * Outer key: tenant identifier ("root" when no tenant is set). Middle key: organization
	 * identifier ("*" when no organization is set). Inner key: model identifier.
	 * @internal
	 */
	private readonly _checkCache: Map<string, Map<string, Map<string, LfuCache<boolean>>>>;

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

		this._loggingComponent = ComponentFactory.getIfExists<ILoggingComponent>(
			options?.loggingComponentType
		);
		this._telemetryComponent = ComponentFactory.getIfExists<ITelemetryComponent>(
			options?.telemetryComponentType
		);

		this._defaultNamespace = options?.config?.defaultNamespace ?? names[0];
		this._authorizationModelId =
			options?.config?.authorizationModelId ?? AuthorizationService.DEFAULT_AUTHORIZATION_MODEL_ID;
		this._escalatedPrivilegeRole =
			options?.config?.escalatedPrivilegeRole ??
			AuthorizationService.DEFAULT_ESCALATED_PRIVILEGE_ROLE;

		this._checkCacheConfig = {
			capacity: options?.config?.checkCacheCapacity,
			ttiMs: options?.config?.checkCacheTtiMs ?? 60000
		};
		this._checkCache = new Map<string, Map<string, Map<string, LfuCache<boolean>>>>();
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
		if (Is.undefined(this._telemetryComponent)) {
			return;
		}
		await MetricHelper.createMetrics(this._telemetryComponent, AUTHORIZATION_METRICS);
	}

	/**
	 * Build the authorization model by applying a set of policies and role inheritances.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param model The policies and role inheritances to apply.
	 * @returns Nothing.
	 */
	public async build(modelId: string, model: IAuthorizationModel): Promise<void> {
		this.guardNoSeparator(nameof(modelId), modelId);
		const connector = this.getConnector();
		const contextIds = await ContextIdStore.getContextIds();
		const callerId = contextIds?.[ContextIdKeys.User];

		if (
			Is.stringValue(callerId) &&
			!(await this.isCallerEscalatedPrivilege(modelId, connector, callerId))
		) {
			if (Is.stringValue(this._authorizationModelId) && modelId === this._authorizationModelId) {
				throw new UnauthorizedError(AuthorizationService.CLASS_NAME, "systemModelBuildDenied");
			}
			const { entities } = await connector.getAllPolicies(modelId, undefined, undefined, 1);
			if (entities.length > 0) {
				const allowed = await connector.check(modelId, callerId, "authorization", "build");
				if (!allowed) {
					throw new UnauthorizedError(AuthorizationService.CLASS_NAME, "escalationDenied");
				}
			}
			const hasBuildPolicy =
				model.policies?.some(
					(p: IAuthorizationPolicy) =>
						p.subject === callerId && p.object === "authorization" && p.action === "build"
				) ?? false;
			if (!hasBuildPolicy) {
				model = {
					...model,
					policies: [
						...(model.policies ?? []),
						{ subject: callerId, object: "authorization", action: "build" }
					]
				};
			}
		}

		try {
			await connector.build(modelId, model);
			this.invalidateCacheForModel(modelId);
			await this._loggingComponent?.log({
				level: "info",
				source: AuthorizationService.CLASS_NAME,
				ts: Date.now(),
				message: "modelBuilt",
				data: { modelId }
			});
		} catch (error) {
			throw new GeneralError(AuthorizationService.CLASS_NAME, "buildFailed", undefined, error);
		}
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
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(subject), subject);
		this.guardNoSeparator(nameof(object), object);
		this.guardNoSeparator(nameof(action), action);

		try {
			const connector = this.getConnector();
			const scope = await this.getScope();
			const key = this.buildCacheKey(subject, object, action);
			return await this.getScopeCache(modelId, scope.tenantId, scope.organizationId).getOrSet(
				key,
				async () => connector.check(modelId, subject, object, action)
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
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(subject), subject);
		this.guardNoSeparator(nameof(object), object);
		this.guardNoSeparator(nameof(action), action);

		const connector = this.getConnector();
		await this.guardCallerPolicyEscalation(modelId, connector, subject);

		try {
			await connector.addPolicy(modelId, subject, object, action);
			await this.invalidateCacheForRoleSubjects(modelId, subject);
			await this._loggingComponent?.log({
				level: "info",
				source: AuthorizationService.CLASS_NAME,
				ts: Date.now(),
				message: "policyAdded",
				data: { modelId, subject, object, action }
			});

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
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(subject), subject);
		this.guardNoSeparator(nameof(object), object);
		this.guardNoSeparator(nameof(action), action);

		try {
			const connector = this.getConnector();
			await connector.removePolicy(modelId, subject, object, action);
			await this.invalidateCacheForRoleSubjects(modelId, subject);
			await this._loggingComponent?.log({
				level: "info",
				source: AuthorizationService.CLASS_NAME,
				ts: Date.now(),
				message: "policyRemoved",
				data: { modelId, subject, object, action }
			});

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
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(subject), subject);

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
		this.guardNoSeparator(nameof(modelId), modelId);
		if (subject !== undefined) {
			this.guardNoSeparator(nameof(subject), subject);
		}

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
		this.guardNoSeparator(nameof(modelId), modelId);

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
		this.guardNoSeparator(nameof(modelId), modelId);
		Guards.array<string>(AuthorizationService.CLASS_NAME, nameof(roles), roles);
		for (const role of roles) {
			this.guardNoSeparator(nameof(role), role);
		}

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
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(subject), subject);
		this.guardNoSeparator(nameof(role), role);

		const connector = this.getConnector();
		await this.guardCallerEscalation(modelId, connector, "escalationDenied", [role]);

		try {
			await connector.addRoleForSubject(modelId, subject, role);
			await this.invalidateModelCacheByPrefix(modelId, subject);
			await this._loggingComponent?.log({
				level: "info",
				source: AuthorizationService.CLASS_NAME,
				ts: Date.now(),
				message: "roleAssigned",
				data: { modelId, subject, role }
			});

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
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(subject), subject);
		this.guardNoSeparator(nameof(role), role);

		const connector = this.getConnector();
		await this.guardCallerEscalation(modelId, connector, "escalationDenied", [role]);

		try {
			await connector.removeRoleForSubject(modelId, subject, role);
			await this.invalidateModelCacheByPrefix(modelId, subject);
			await this._loggingComponent?.log({
				level: "info",
				source: AuthorizationService.CLASS_NAME,
				ts: Date.now(),
				message: "roleRemoved",
				data: { modelId, subject, role }
			});

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
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(subject), subject);

		const connector = this.getConnector();
		const roles = await connector.getRolesForSubject(modelId, subject);
		await this.guardCallerEscalation(modelId, connector, "escalationDenied", roles);

		try {
			await connector.removeAllRolesForSubject(modelId, subject);
			await this.invalidateModelCacheByPrefix(modelId, subject);
			await this._loggingComponent?.log({
				level: "info",
				source: AuthorizationService.CLASS_NAME,
				ts: Date.now(),
				message: "allRolesRemoved",
				data: { modelId, subject }
			});

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
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(subject), subject);

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
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(role), role);

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
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(subject), subject);
		this.guardNoSeparator(nameof(role), role);

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
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(role), role);
		this.guardNoSeparator(nameof(inheritsFrom), inheritsFrom);

		const connector = this.getConnector();
		await this.guardCallerEscalation(modelId, connector, "escalationDenied", [role, inheritsFrom]);

		try {
			await connector.addRoleInheritance(modelId, role, inheritsFrom);
			await this.invalidateCacheForRoleSubjects(modelId, role);
			await this._loggingComponent?.log({
				level: "info",
				source: AuthorizationService.CLASS_NAME,
				ts: Date.now(),
				message: "inheritanceAdded",
				data: { modelId, role, inheritsFrom }
			});

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
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(role), role);
		this.guardNoSeparator(nameof(inheritsFrom), inheritsFrom);

		const connector = this.getConnector();
		await this.guardCallerEscalation(modelId, connector, "escalationDenied", [role]);

		try {
			await connector.removeRoleInheritance(modelId, role, inheritsFrom);
			await this.invalidateCacheForRoleSubjects(modelId, role);
			await this._loggingComponent?.log({
				level: "info",
				source: AuthorizationService.CLASS_NAME,
				ts: Date.now(),
				message: "inheritanceRemoved",
				data: { modelId, role, inheritsFrom }
			});

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
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(role), role);

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
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(role), role);

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
	 * Build a cache key for a check result.
	 * @param subject The subject.
	 * @param object The object.
	 * @param action The action.
	 * @returns The cache key string.
	 * @internal
	 */
	private buildCacheKey(subject: string, object: string, action: string): string {
		return `${subject}|${object}|${action}`;
	}

	/**
	 * Resolve the scope partitioning the check cache from the ambient tenant and organization
	 * context ids. The organization follows the user organization when present, falling back
	 * to the deployment organization.
	 * @returns The tenant and organization identifiers.
	 * @internal
	 */
	private async getScope(): Promise<{ tenantId: string; organizationId: string }> {
		const contextIds = await ContextIdStore.getContextIds();
		return {
			tenantId: contextIds?.[ContextIdKeys.Tenant] ?? ROOT_TENANT,
			organizationId:
				contextIds?.[ContextIdKeys.UserOrganization] ??
				contextIds?.[ContextIdKeys.Organization] ??
				GLOBAL_ORGANIZATION
		};
	}

	/**
	 * Get or create the per-tenant, per-organization, per-model LFU cache.
	 * @param modelId The model identifier.
	 * @param tenantId The tenant identifier.
	 * @param organizationId The organization identifier.
	 * @returns The LFU cache for the scope and model.
	 * @internal
	 */
	private getScopeCache(
		modelId: string,
		tenantId: string,
		organizationId: string
	): LfuCache<boolean> {
		let organizationMap = this._checkCache.get(tenantId);
		if (Is.empty(organizationMap)) {
			organizationMap = new Map<string, Map<string, LfuCache<boolean>>>();
			this._checkCache.set(tenantId, organizationMap);
		}
		let modelMap = organizationMap.get(organizationId);
		if (Is.empty(modelMap)) {
			modelMap = new Map<string, LfuCache<boolean>>();
			organizationMap.set(organizationId, modelMap);
		}
		let cache = modelMap.get(modelId);
		if (Is.empty(cache)) {
			cache = new LfuCache<boolean>(this._checkCacheConfig);
			modelMap.set(modelId, cache);
		}
		return cache;
	}

	/**
	 * Get the existing per-model caches a mutation in the current scope can affect. Tenants
	 * are physically separated, so only the current tenant's caches are affected: the cache
	 * for the exact organization (returned for fine-grained eviction) and, because global
	 * rules match every organization, all of the tenant's other organization caches when the
	 * mutation has no organization context (returned for full eviction).
	 * @param modelId The model identifier.
	 * @returns The exact-scope cache if it exists and the other affected model cache maps.
	 * @internal
	 */
	private async getAffectedModelCaches(modelId: string): Promise<{
		exact?: LfuCache<boolean>;
		others: Map<string, LfuCache<boolean>>[];
	}> {
		const scope = await this.getScope();
		const organizationMap = this._checkCache.get(scope.tenantId);

		let exact: LfuCache<boolean> | undefined;
		const others: Map<string, LfuCache<boolean>>[] = [];
		if (!Is.empty(organizationMap)) {
			exact = organizationMap.get(scope.organizationId)?.get(modelId);
			if (scope.organizationId === GLOBAL_ORGANIZATION) {
				for (const [organizationId, modelMap] of organizationMap) {
					if (organizationId !== GLOBAL_ORGANIZATION && modelMap.has(modelId)) {
						others.push(modelMap);
					}
				}
			}
		}
		return { exact, others };
	}

	/**
	 * Evict cached check() results for every user that transitively holds the given role.
	 * BFS-traverses child roles (those that inherit FROM the given role) so that transitive
	 * holders are also evicted. Also evicts cache entries whose key uses the role name as the
	 * subject segment, which covers policies assigned directly to a user ID.
	 * @param modelId The model identifier (for connector queries).
	 * @param role The role or subject whose associated user IDs should have their cache evicted.
	 * @internal
	 */
	private async invalidateCacheForRoleSubjects(modelId: string, role: string): Promise<void> {
		const affected = await this.getAffectedModelCaches(modelId);
		for (const modelMap of affected.others) {
			modelMap.delete(modelId);
		}
		const scopeCache = affected.exact;
		if (!Is.empty(scopeCache)) {
			const connector = this.getConnector();
			const visited = new Set<string>();
			const queue = [role];

			while (queue.length > 0) {
				const current = queue.shift();
				if (!Is.empty(current) && !visited.has(current)) {
					visited.add(current);

					this.invalidateCacheByPrefix(scopeCache, current);

					const subjects = await connector.getSubjectsForRole(modelId, current);
					for (const subject of subjects) {
						this.invalidateCacheByPrefix(scopeCache, subject);
					}

					const children = await connector.getChildRoles(modelId, current);
					for (const child of children) {
						if (!visited.has(child)) {
							queue.push(child);
						}
					}
				}
			}
		}
	}

	/**
	 * Evict all cached check() results whose key starts with the given subject/role prefix.
	 * @param modelId The model identifier (for connector queries).
	 * @param part The subject or role name to use as the key prefix segment.
	 * @internal
	 */
	private async invalidateModelCacheByPrefix(modelId: string, part: string): Promise<void> {
		const affected = await this.getAffectedModelCaches(modelId);
		for (const modelMap of affected.others) {
			modelMap.delete(modelId);
		}
		if (!Is.empty(affected.exact)) {
			this.invalidateCacheByPrefix(affected.exact, part);
		}
	}

	/**
	 * Evict all cached check() results whose key starts with the given subject/role prefix.
	 * @param scopeCache The resolved LFU cache for the current scope and model.
	 * @param part The subject or role name to use as the key prefix segment.
	 * @internal
	 */
	private invalidateCacheByPrefix(scopeCache: LfuCache<boolean>, part: string): void {
		const prefix = `${part}|`;
		for (const key of scopeCache.keys()) {
			if (key.startsWith(prefix)) {
				scopeCache.delete(key);
			}
		}
	}

	/**
	 * Evict all cached check() results for the given model across all scopes.
	 * @param modelId The model identifier.
	 * @internal
	 */
	private invalidateCacheForModel(modelId: string): void {
		for (const organizationMap of this._checkCache.values()) {
			for (const modelMap of organizationMap.values()) {
				modelMap.delete(modelId);
			}
		}
	}

	/**
	 * Throw a GeneralError if the value contains the pipe separator character.
	 * @param fieldName The field name for the error context.
	 * @param value The value to validate.
	 * @throws GeneralError If the value contains a pipe character.
	 * @internal
	 */
	private guardNoSeparator(fieldName: string, value: string): void {
		Guards.stringValue(AuthorizationService.CLASS_NAME, fieldName, value);
		if (value.includes("|")) {
			throw new GeneralError(AuthorizationService.CLASS_NAME, "containsSeparator", { fieldName });
		}
	}

	/**
	 * Returns true when the caller holds the configured escalated-privilege role in the given model,
	 * granting them unrestricted access to all mutation operations.
	 * @param modelId The model identifier.
	 * @param connector The authorization connector.
	 * @param callerId The caller's user identifier.
	 * @returns True if the caller holds the escalated-privilege role.
	 * @internal
	 */
	private async isCallerEscalatedPrivilege(
		modelId: string,
		connector: IAuthorizationConnector,
		callerId: string
	): Promise<boolean> {
		const callerRoles = await connector.getRolesForSubject(modelId, callerId);
		return callerRoles.includes(this._escalatedPrivilegeRole);
	}

	/**
	 * Deny the caller if any of the supplied role names are in their forbidden (descendant) set.
	 * No-ops when there is no user in the request context (system-level call).
	 * @param modelId The model identifier.
	 * @param connector The authorization connector.
	 * @param errorKey The locale error key to throw on denial.
	 * @param roles One or more role names to check.
	 * @internal
	 */
	private async guardCallerEscalation(
		modelId: string,
		connector: IAuthorizationConnector,
		errorKey: string,
		roles: string[]
	): Promise<void> {
		const contextIds = await ContextIdStore.getContextIds();
		const callerId = contextIds?.[ContextIdKeys.User];
		if (Is.stringValue(callerId)) {
			if (await this.isCallerEscalatedPrivilege(modelId, connector, callerId)) {
				return;
			}
			const forbidden = await this.buildCallerForbiddenSet(modelId, connector, callerId);
			if (roles.some(r => forbidden.has(r))) {
				throw new UnauthorizedError(AuthorizationService.CLASS_NAME, errorKey);
			}
		}
	}

	/**
	 * Deny the caller if the policy subject is their own user ID or any role they hold or
	 * inherit from. No-ops when there is no user in the request context (system-level call).
	 * @param modelId The model identifier.
	 * @param connector The authorization connector.
	 * @param subject The policy subject to check.
	 * @internal
	 */
	private async guardCallerPolicyEscalation(
		modelId: string,
		connector: IAuthorizationConnector,
		subject: string
	): Promise<void> {
		const contextIds = await ContextIdStore.getContextIds();
		const callerId = contextIds?.[ContextIdKeys.User];
		if (Is.stringValue(callerId)) {
			if (await this.isCallerEscalatedPrivilege(modelId, connector, callerId)) {
				return;
			}
			const affected = await this.buildCallerAffectedSet(modelId, connector, callerId);
			if (subject === callerId || affected.has(subject)) {
				throw new UnauthorizedError(AuthorizationService.CLASS_NAME, "escalationDenied");
			}
		}
	}

	/**
	 * BFS over getChildRoles to build the set of roles the caller must not mutate. The set includes
	 * all roles more privileged than the caller and the escalated-privilege role with its descendants.
	 * @param modelId The model identifier.
	 * @param connector The authorization connector.
	 * @param callerId The calling user identifier.
	 * @returns The forbidden (descendant) role set.
	 * @internal
	 */
	private async buildCallerForbiddenSet(
		modelId: string,
		connector: IAuthorizationConnector,
		callerId: string
	): Promise<Set<string>> {
		const callerRoles = await connector.getRolesForSubject(modelId, callerId);
		const forbidden = new Set<string>([this._escalatedPrivilegeRole]);
		const visited = new Set<string>([...callerRoles, this._escalatedPrivilegeRole]);
		const queue = [...callerRoles, this._escalatedPrivilegeRole];
		while (queue.length > 0) {
			const current = queue.shift();
			if (!Is.empty(current)) {
				const children = await connector.getChildRoles(modelId, current);
				for (const child of children) {
					if (!visited.has(child)) {
						visited.add(child);
						forbidden.add(child);
						queue.push(child);
					}
				}
			}
		}
		return forbidden;
	}

	/**
	 * BFS over getParentRoles to build the set of all roles the caller directly holds or
	 * transitively inherits from. Adding a policy for any role in this set would grant the
	 * caller new permissions.
	 * @param modelId The model identifier.
	 * @param connector The authorization connector.
	 * @param callerId The calling user identifier.
	 * @returns The affected (direct + ancestor) role set.
	 * @internal
	 */
	private async buildCallerAffectedSet(
		modelId: string,
		connector: IAuthorizationConnector,
		callerId: string
	): Promise<Set<string>> {
		const callerRoles = await connector.getRolesForSubject(modelId, callerId);
		const affected = new Set<string>(callerRoles);
		const queue = [...callerRoles];
		while (queue.length > 0) {
			const current = queue.shift();
			if (!Is.empty(current)) {
				const parents = await connector.getParentRoles(modelId, current);
				for (const parent of parents) {
					if (!affected.has(parent)) {
						affected.add(parent);
						queue.push(parent);
					}
				}
			}
		}
		return affected;
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
