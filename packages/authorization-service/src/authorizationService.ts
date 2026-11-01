// Copyright 2026 IOTA Stiftung.
// Copyright 2026 3Sixty Trade Ltd.
// SPDX-License-Identifier: Apache-2.0.
import {
	AUTHORIZATION_METRIC_IDS,
	AUTHORIZATION_METRICS,
	AuthorizationConnectorFactory,
	type IAuthorizationComponent,
	type IAuthorizationConnector,
	type IAuthorizationModel,
	type IAuthorizationPolicy
} from "@3sixty/authorization-models";
import { ContextIdKeys, ContextIdStore } from "@3sixty/context";
import {
	ComponentFactory,
	GeneralError,
	GuardError,
	Guards,
	Is,
	LfuCache,
	UnauthorizedError
} from "@3sixty/core";
import type { ILoggingComponent } from "@3sixty/logging-models";
import { nameof } from "@3sixty/nameof";
import { MetricHelper, type ITelemetryComponent } from "@3sixty/telemetry-models";
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
	 * The model identifier that is reserved for system-only use.
	 */
	public static readonly DEFAULT_AUTHORIZATION_MODEL_ID: string = "system";

	/**
	 * The role that bypasses all escalation guards when held by the caller.
	 */
	public static readonly DEFAULT_ESCALATED_PRIVILEGE_ROLE: string = "global-admin";

	/**
	 * The authorization connector of the default namespace.
	 * @internal
	 */
	private readonly _authorizationConnector: IAuthorizationConnector;

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
	private readonly _authorizationModelId: string;

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
	 * Per-tenant, per-model LFU caches for check() results.
	 * Outer key: tenant identifier ("root" when no tenant is set). Inner key: model identifier.
	 * @internal
	 */
	private readonly _checkCache: Map<string, Map<string, LfuCache<boolean>>>;

	/**
	 * Incremented on every cache invalidation so check() can discard results loaded concurrently
	 * with a mutation. The cache is local to this instance and is not shared across processes.
	 * @internal
	 */
	private _cacheGeneration: number;

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

		this._authorizationConnector = AuthorizationConnectorFactory.get<IAuthorizationConnector>(
			options?.config?.defaultNamespace ?? names[0]
		);
		this._authorizationModelId =
			options?.config?.authorizationModelId ?? AuthorizationService.DEFAULT_AUTHORIZATION_MODEL_ID;
		this._escalatedPrivilegeRole =
			options?.config?.escalatedPrivilegeRole ??
			AuthorizationService.DEFAULT_ESCALATED_PRIVILEGE_ROLE;

		this._checkCacheConfig = {
			capacity: options?.config?.checkCacheCapacity,
			ttiMs: options?.config?.checkCacheTtiMs ?? 60000
		};
		this._checkCache = new Map<string, Map<string, LfuCache<boolean>>>();
		this._cacheGeneration = 0;
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
		Guards.object<IAuthorizationModel>(AuthorizationService.CLASS_NAME, nameof(model), model);
		for (const policy of model.policies ?? []) {
			this.guardNoSeparator(nameof(policy.subject), policy.subject);
			this.guardNoSeparator(nameof(policy.object), policy.object);
			this.guardNoSeparator(nameof(policy.action), policy.action);
		}
		for (const inheritance of model.roleInheritances ?? []) {
			this.guardNoSeparator(nameof(inheritance.role), inheritance.role);
			this.guardNoSeparator(nameof(inheritance.inheritsFrom), inheritance.inheritsFrom);
		}
		const contextIds = await ContextIdStore.getContextIds();
		const callerId = contextIds?.[ContextIdKeys.Account];

		if (Is.stringValue(callerId) && !(await this.isCallerEscalatedPrivilege(modelId, callerId))) {
			if (Is.stringValue(this._authorizationModelId) && modelId === this._authorizationModelId) {
				throw new UnauthorizedError(AuthorizationService.CLASS_NAME, "systemModelBuildDenied");
			}
			const { entities } = await this._authorizationConnector.getAllPolicies(
				modelId,
				undefined,
				undefined,
				1
			);
			if (entities.length > 0) {
				const allowed = await this._authorizationConnector.check(
					modelId,
					callerId,
					"authorization",
					"build"
				);
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
			await this._authorizationConnector.build(modelId, model);
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
			const contextIds = await ContextIdStore.getContextIds();
			const tenantId = contextIds?.[ContextIdKeys.Tenant] ?? "root";
			const key = this.buildCacheKey(subject, object, action);
			const cache = this.getTenantCache(modelId, tenantId);
			const generation = this._cacheGeneration;
			const allowed = await cache.getOrSet(key, async () =>
				this._authorizationConnector.check(modelId, subject, object, action)
			);
			if (generation !== this._cacheGeneration) {
				// A mutation was invalidated while loading, so the cached result may be stale.
				cache.delete(key);
			}
			return allowed;
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

		await this.guardCallerPolicyEscalation(modelId, subject);

		try {
			await this._authorizationConnector.addPolicy(modelId, subject, object, action);
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

		await this.guardCallerPolicyRemoval(modelId, subject, object, action);

		try {
			await this._authorizationConnector.removePolicy(modelId, subject, object, action);
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
			return await this._authorizationConnector.getPoliciesForSubject(
				modelId,
				subject,
				cursor,
				limit
			);
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
			return await this._authorizationConnector.getAllPolicies(modelId, subject, cursor, limit);
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
			return await this._authorizationConnector.getAllRoles(modelId, cursor, limit);
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
			return await this._authorizationConnector.hasRoles(modelId, roles);
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

		await this.guardCallerEscalation(modelId, "escalationDenied", [role], {
			denySelf: subject
		});

		try {
			await this._authorizationConnector.addRoleForSubject(modelId, subject, role);
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

		await this.guardCallerEscalation(modelId, "escalationDenied", [role], {
			protectedSubject: subject
		});

		try {
			await this._authorizationConnector.removeRoleForSubject(modelId, subject, role);
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

		const roles = await this._authorizationConnector.getRolesForSubject(modelId, subject);
		await this.guardCallerEscalation(modelId, "escalationDenied", roles, {
			protectedSubject: subject
		});

		try {
			await this._authorizationConnector.removeAllRolesForSubject(modelId, subject);
			await this.invalidateModelCacheByPrefix(modelId, subject);
			await this._loggingComponent?.log({
				level: "info",
				source: AuthorizationService.CLASS_NAME,
				ts: Date.now(),
				message: "allRolesRemoved",
				data: { modelId, subject }
			});

			for (let i = 0; i < roles.length; i++) {
				await MetricHelper.metricIncrement(
					this._telemetryComponent,
					AUTHORIZATION_METRIC_IDS.RolesRemoved
				);
			}
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
			return await this._authorizationConnector.getRolesForSubject(modelId, subject);
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
			return await this._authorizationConnector.getSubjectsForRole(modelId, role);
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
			return await this._authorizationConnector.hasRoleForSubject(modelId, subject, role);
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

		await this.guardCallerEscalation(modelId, "escalationDenied", [role, inheritsFrom], {
			denyAffectedRole: role
		});

		try {
			await this._authorizationConnector.addRoleInheritance(modelId, role, inheritsFrom);
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

		await this.guardCallerEscalation(modelId, "escalationDenied", [role]);

		try {
			await this._authorizationConnector.removeRoleInheritance(modelId, role, inheritsFrom);
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
			return await this._authorizationConnector.getParentRoles(modelId, role);
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
			return await this._authorizationConnector.getChildRoles(modelId, role);
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
	 * Get or create the per-tenant, per-model LFU cache.
	 * @param modelId The model identifier.
	 * @param tenantId The tenant identifier.
	 * @returns The LFU cache for the tenant and model.
	 * @internal
	 */
	private getTenantCache(modelId: string, tenantId: string): LfuCache<boolean> {
		let modelMap = this._checkCache.get(tenantId);
		if (Is.empty(modelMap)) {
			modelMap = new Map<string, LfuCache<boolean>>();
			this._checkCache.set(tenantId, modelMap);
		}
		let cache = modelMap.get(modelId);
		if (Is.empty(cache)) {
			cache = new LfuCache<boolean>(this._checkCacheConfig);
			modelMap.set(modelId, cache);
		}
		return cache;
	}

	/**
	 * Get the per-tenant, per-model LFU cache if it exists.
	 * @param modelId The model identifier.
	 * @returns The LFU cache for the tenant and model, or undefined if it doesn't exist.
	 * @internal
	 */
	private async getModelCache(modelId: string): Promise<LfuCache<boolean> | undefined> {
		const contextIds = await ContextIdStore.getContextIds();
		const tenantId = contextIds?.[ContextIdKeys.Tenant] ?? "root";
		return this._checkCache.get(tenantId)?.get(modelId);
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
		this._cacheGeneration++;
		const tenantCache = await this.getModelCache(modelId);
		if (!Is.empty(tenantCache)) {
			const visited = new Set<string>();
			const queue = [role];

			while (queue.length > 0) {
				const current = queue.shift();
				if (!Is.empty(current) && !visited.has(current)) {
					visited.add(current);

					this.invalidateCacheByPrefix(tenantCache, current);

					const subjects = await this._authorizationConnector.getSubjectsForRole(modelId, current);
					for (const subject of subjects) {
						this.invalidateCacheByPrefix(tenantCache, subject);
					}

					const children = await this._authorizationConnector.getChildRoles(modelId, current);
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
		this._cacheGeneration++;
		const tenantCache = await this.getModelCache(modelId);
		if (!Is.empty(tenantCache)) {
			this.invalidateCacheByPrefix(tenantCache, part);
		}
	}

	/**
	 * Evict all cached check() results whose key starts with the given subject/role prefix.
	 * @param tenantCache The resolved LFU cache for the current tenant and model.
	 * @param part The subject or role name to use as the key prefix segment.
	 * @internal
	 */
	private invalidateCacheByPrefix(tenantCache: LfuCache<boolean>, part: string): void {
		const prefix = `${part}|`;
		for (const key of tenantCache.keys()) {
			if (key.startsWith(prefix)) {
				tenantCache.delete(key);
			}
		}
	}

	/**
	 * Evict all cached check() results for the given model across all tenants.
	 * @param modelId The model identifier.
	 * @internal
	 */
	private invalidateCacheForModel(modelId: string): void {
		this._cacheGeneration++;
		for (const modelMap of this._checkCache.values()) {
			modelMap.delete(modelId);
		}
	}

	/**
	 * Throw a GuardError if the value contains the pipe separator character.
	 * @param fieldName The field name for the error context.
	 * @param value The value to validate.
	 * @throws GuardError If the value contains a pipe character.
	 * @internal
	 */
	private guardNoSeparator(fieldName: string, value: string): void {
		Guards.stringValue(AuthorizationService.CLASS_NAME, fieldName, value);
		if (value.includes("|")) {
			throw new GuardError(AuthorizationService.CLASS_NAME, "containsSeparator", fieldName, value);
		}
	}

	/**
	 * Returns true when the caller holds the configured escalated-privilege role in the given model,
	 * granting them unrestricted access to all mutation operations.
	 * @param modelId The model identifier.
	 * @param callerId The caller's user identifier.
	 * @returns True if the caller holds the escalated-privilege role.
	 * @internal
	 */
	private async isCallerEscalatedPrivilege(modelId: string, callerId: string): Promise<boolean> {
		const callerRoles = await this._authorizationConnector.getRolesForSubject(modelId, callerId);
		return callerRoles.includes(this._escalatedPrivilegeRole);
	}

	/**
	 * Deny the caller if any of the supplied role names are in their forbidden (descendant) set.
	 * No-ops when there is no account in the request context (system-level call) or the caller holds
	 * the escalated-privilege role.
	 * @param modelId The model identifier.
	 * @param errorKey The locale error key to throw on denial.
	 * @param roles One or more role names to check.
	 * @param options Additional checks to apply.
	 * @param options.denySelf Deny when this subject is the caller.
	 * @param options.protectedSubject Deny when this subject holds a forbidden role.
	 * @param options.denyAffectedRole Deny when this role is held or inherited by the caller.
	 * @internal
	 */
	private async guardCallerEscalation(
		modelId: string,
		errorKey: string,
		roles: string[],
		options?: { denySelf?: string; protectedSubject?: string; denyAffectedRole?: string }
	): Promise<void> {
		const contextIds = await ContextIdStore.getContextIds();
		const callerId = contextIds?.[ContextIdKeys.Account];
		if (Is.stringValue(callerId)) {
			if (await this.isCallerEscalatedPrivilege(modelId, callerId)) {
				return;
			}
			if (options?.denySelf === callerId) {
				throw new UnauthorizedError(AuthorizationService.CLASS_NAME, errorKey);
			}
			const forbidden = await this.buildCallerForbiddenSet(modelId, callerId);
			if (roles.some(r => forbidden.has(r))) {
				throw new UnauthorizedError(AuthorizationService.CLASS_NAME, errorKey);
			}
			if (
				Is.stringValue(options?.protectedSubject) &&
				(await this.isProtectedSubject(modelId, options.protectedSubject, forbidden))
			) {
				throw new UnauthorizedError(AuthorizationService.CLASS_NAME, errorKey);
			}
			if (Is.stringValue(options?.denyAffectedRole)) {
				const affected = await this.buildCallerAffectedSet(modelId, callerId);
				if (affected.has(options.denyAffectedRole)) {
					throw new UnauthorizedError(AuthorizationService.CLASS_NAME, errorKey);
				}
			}
		}
	}

	/**
	 * Deny removing a policy whose subject is more privileged than the caller, or removing a
	 * model build policy when the caller cannot build the model themselves. No-ops when there is
	 * no account in the request context or the caller holds the escalated-privilege role.
	 * @param modelId The model identifier.
	 * @param subject The policy subject.
	 * @param object The policy object.
	 * @param action The policy action.
	 * @internal
	 */
	private async guardCallerPolicyRemoval(
		modelId: string,
		subject: string,
		object: string,
		action: string
	): Promise<void> {
		const contextIds = await ContextIdStore.getContextIds();
		const callerId = contextIds?.[ContextIdKeys.Account];
		if (Is.stringValue(callerId)) {
			if (await this.isCallerEscalatedPrivilege(modelId, callerId)) {
				return;
			}
			const forbidden = await this.buildCallerForbiddenSet(modelId, callerId);
			if (await this.isProtectedSubject(modelId, subject, forbidden)) {
				throw new UnauthorizedError(AuthorizationService.CLASS_NAME, "escalationDenied");
			}
			if (
				object === "authorization" &&
				action === "build" &&
				!(await this._authorizationConnector.check(modelId, callerId, object, action))
			) {
				throw new UnauthorizedError(AuthorizationService.CLASS_NAME, "escalationDenied");
			}
		}
	}

	/**
	 * Returns true when the subject is a forbidden role or a subject holding a forbidden role.
	 * @param modelId The model identifier.
	 * @param subject The subject or role to test.
	 * @param forbidden The caller's forbidden role set.
	 * @returns True if the subject is protected from the caller.
	 * @internal
	 */
	private async isProtectedSubject(
		modelId: string,
		subject: string,
		forbidden: Set<string>
	): Promise<boolean> {
		if (forbidden.has(subject)) {
			return true;
		}
		const subjectRoles = await this._authorizationConnector.getRolesForSubject(modelId, subject);
		return subjectRoles.some(r => forbidden.has(r));
	}

	/**
	 * Deny the caller if the policy subject is their own user ID or any role they hold or
	 * inherit from. No-ops when there is no account in the request context (system-level call).
	 * @param modelId The model identifier.
	 * @param subject The policy subject to check.
	 * @internal
	 */
	private async guardCallerPolicyEscalation(modelId: string, subject: string): Promise<void> {
		const contextIds = await ContextIdStore.getContextIds();
		const callerId = contextIds?.[ContextIdKeys.Account];
		if (Is.stringValue(callerId)) {
			if (await this.isCallerEscalatedPrivilege(modelId, callerId)) {
				return;
			}
			const affected = await this.buildCallerAffectedSet(modelId, callerId);
			if (subject === callerId || affected.has(subject)) {
				throw new UnauthorizedError(AuthorizationService.CLASS_NAME, "escalationDenied");
			}
		}
	}

	/**
	 * BFS over getChildRoles to build the set of roles the caller must not mutate. The set includes
	 * all roles more privileged than the caller and the escalated-privilege role with its descendants.
	 * @param modelId The model identifier.
	 * @param callerId The calling user identifier.
	 * @returns The forbidden (descendant) role set.
	 * @internal
	 */
	private async buildCallerForbiddenSet(modelId: string, callerId: string): Promise<Set<string>> {
		const callerRoles = await this._authorizationConnector.getRolesForSubject(modelId, callerId);
		const forbidden = new Set<string>([this._escalatedPrivilegeRole]);
		const visited = new Set<string>([...callerRoles, this._escalatedPrivilegeRole]);
		const queue = [...callerRoles, this._escalatedPrivilegeRole];
		while (queue.length > 0) {
			const current = queue.shift();
			if (!Is.empty(current)) {
				const children = await this._authorizationConnector.getChildRoles(modelId, current);
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
	 * @param callerId The calling user identifier.
	 * @returns The affected (direct + ancestor) role set.
	 * @internal
	 */
	private async buildCallerAffectedSet(modelId: string, callerId: string): Promise<Set<string>> {
		const callerRoles = await this._authorizationConnector.getRolesForSubject(modelId, callerId);
		const affected = new Set<string>(callerRoles);
		const queue = [...callerRoles];
		while (queue.length > 0) {
			const current = queue.shift();
			if (!Is.empty(current)) {
				const parents = await this._authorizationConnector.getParentRoles(modelId, current);
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
}
