// Copyright 2026 IOTA Stiftung.
// Copyright 2026 3Sixty Trade Ltd.
// SPDX-License-Identifier: Apache-2.0.
import type {
	IAuthorizationConnector,
	IAuthorizationModel,
	IAuthorizationPolicy
} from "@3sixty/authorization-models";
import { ContextIdKeys, ContextIdStore } from "@3sixty/context";
import {
	BaseError,
	ComponentFactory,
	Converter,
	GeneralError,
	GuardError,
	Guards,
	Is,
	Mutex,
	StringHelper
} from "@3sixty/core";
import { Sha256 } from "@3sixty/crypto";
import type { ILoggingComponent } from "@3sixty/logging-models";
import { nameof } from "@3sixty/nameof";
import { FetchHelper, HttpMethod, type IHttpHeaders } from "@3sixty/web";
import type { ICasbinAuthorizationConnectorConfig } from "./models/ICasbinAuthorizationConnectorConfig.js";
import type { ICasbinAuthorizationConnectorConstructorOptions } from "./models/ICasbinAuthorizationConnectorConstructorOptions.js";
import type { ICasbinServerResponse } from "./models/ICasbinServerResponse.js";
import type { ICasdoorPolicyRule } from "./models/ICasdoorPolicyRule.js";

/**
 * A connector that implements the IAuthorizationConnector interface using the Casbin server REST API.
 */
export class CasbinAuthorizationConnector implements IAuthorizationConnector {
	/**
	 * The namespace for the connector.
	 */
	public static readonly NAMESPACE: string = "casbin";

	/**
	 * Runtime name for the class.
	 */
	public static readonly CLASS_NAME: string = nameof<CasbinAuthorizationConnector>();

	/**
	 * Value stored in V2 of a "g" rule to mark it as a role assignment.
	 * Casdoor's policy API stores every non "p" rule as "g", so the kind is held in V2 instead of a "g2" type.
	 * @internal
	 */
	private static readonly _ASSIGNMENT_MARKER: string = "assigned";

	/**
	 * Value stored in V2 of a "g" rule to mark it as a role inheritance.
	 * @internal
	 */
	private static readonly _INHERITANCE_MARKER: string = "inherits";

	/**
	 * The default page size when no limit is provided.
	 * @internal
	 */
	private static readonly _DEFAULT_PAGE_SIZE: number = 40;

	/**
	 * The name of the Casdoor model created for each tenant and used by its enforcers.
	 * @internal
	 */
	private static readonly _CASDOOR_MODEL_NAME: string = "authorization";

	/**
	 * The component for logging.
	 * @internal
	 */
	private readonly _loggingComponent?: ILoggingComponent;

	/**
	 * The configuration for the connector.
	 * @internal
	 */
	private readonly _config: ICasbinAuthorizationConnectorConfig;

	/**
	 * The base URL for all API calls.
	 * @internal
	 */
	private readonly _baseUrl: string;

	/**
	 * Shared request options for every fetch call.
	 * @internal
	 */
	private readonly _requestOptions: { headers: IHttpHeaders; timeoutMs?: number };

	/**
	 * Set of enforcer IDs (owner/modelId) whose Casdoor enforcers are known to exist.
	 * @internal
	 */
	private readonly _provisionedEnforcers: Set<string>;

	/**
	 * Creates a new instance of the CasbinAuthorizationConnector.
	 * @param options The options for the connector.
	 */
	constructor(options: ICasbinAuthorizationConnectorConstructorOptions) {
		Guards.object<ICasbinAuthorizationConnectorConstructorOptions>(
			CasbinAuthorizationConnector.CLASS_NAME,
			nameof(options),
			options
		);
		Guards.object<ICasbinAuthorizationConnectorConfig>(
			CasbinAuthorizationConnector.CLASS_NAME,
			nameof(options.config),
			options.config
		);
		Guards.stringValue(
			CasbinAuthorizationConnector.CLASS_NAME,
			nameof(options.config.endpoint),
			options.config.endpoint
		);
		Guards.stringValue(
			CasbinAuthorizationConnector.CLASS_NAME,
			nameof(options.config.clientId),
			options.config.clientId
		);
		Guards.stringValue(
			CasbinAuthorizationConnector.CLASS_NAME,
			nameof(options.config.clientSecret),
			options.config.clientSecret
		);

		this._config = options.config;
		this._provisionedEnforcers = new Set<string>();
		this._loggingComponent = ComponentFactory.getIfExists<ILoggingComponent>(
			options.loggingComponentType
		);

		this._baseUrl = StringHelper.trimTrailingSlashes(this._config.endpoint);

		const credentials = Converter.bytesToBase64(
			Converter.utf8ToBytes(`${this._config.clientId}:${this._config.clientSecret}`)
		);
		this._requestOptions = {
			headers: { Authorization: `Basic ${credentials}` },
			timeoutMs: this._config.timeoutMs
		};
	}

	/**
	 * Returns the class name of the component.
	 * @returns The class name of the component.
	 */
	public className(): string {
		return CasbinAuthorizationConnector.CLASS_NAME;
	}

	/**
	 * Bootstrap the connector and verify connectivity.
	 * @param nodeLoggingComponentType The node logging component type.
	 * @returns True if the bootstrapping process was successful.
	 */
	public async bootstrap(nodeLoggingComponentType?: string): Promise<boolean> {
		const nodeLogging =
			ComponentFactory.getIfExists<ILoggingComponent>(nodeLoggingComponentType) ??
			this._loggingComponent;

		try {
			await FetchHelper.fetch(
				CasbinAuthorizationConnector.CLASS_NAME,
				`${this._baseUrl}/api/health`,
				HttpMethod.GET,
				undefined,
				this._requestOptions
			);

			await nodeLogging?.log({
				level: "info",
				source: CasbinAuthorizationConnector.CLASS_NAME,
				ts: Date.now(),
				message: "casbinConnected",
				data: { address: this._config.endpoint }
			});

			return true;
		} catch (err) {
			await nodeLogging?.log({
				level: "error",
				source: CasbinAuthorizationConnector.CLASS_NAME,
				ts: Date.now(),
				message: "casbinConnectionFailed",
				error: BaseError.fromError(err),
				data: { address: this._config.endpoint }
			});
			return false;
		}
	}

	/**
	 * Build the authorization model by applying a set of policies and role inheritances.
	 * @param modelId The model identifier selecting which policy set to use.
	 * @param model The policies and role inheritances to apply.
	 * @returns Nothing.
	 */
	public async build(modelId: string, model: IAuthorizationModel): Promise<void> {
		this.guardModelId(modelId);

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
				CasbinAuthorizationConnector.CLASS_NAME,
				"buildFailed",
				undefined,
				err
			);
		}
	}

	/**
	 * Check whether a subject is permitted to perform an action on an object.
	 * Evaluates RBAC locally, following the subject's role assignments and then role inheritance.
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
		this.guardModelId(modelId);
		this.guardNoSeparator(nameof(subject), subject);
		this.guardNoSeparator(nameof(object), object);
		this.guardNoSeparator(nameof(action), action);

		try {
			const tenantId = await this.getTenantId();
			if (!(await this.enforcerExists(tenantId, modelId))) {
				return false;
			}

			const [grantRules, subjectRules, inheritanceRules] = await Promise.all([
				this.getRules(tenantId, modelId, "p", 1, [object, action]),
				this.getRules(tenantId, modelId, "g", 0, [subject]),
				this.getRules(tenantId, modelId, "g", 2, [CasbinAuthorizationConnector._INHERITANCE_MARKER])
			]);

			const grantees = new Set(
				grantRules.filter(r => r.V1 === object && r.V2 === action).map(r => r.V0)
			);
			if (grantees.has(subject)) {
				return true;
			}

			const parents = new Map<string, string[]>();
			for (const r of inheritanceRules.filter(rule => this.isInheritance(rule))) {
				const list = parents.get(r.V0) ?? [];
				list.push(r.V1);
				parents.set(r.V0, list);
			}

			// First level from assignments only, then follow inheritance upwards.
			const queue = subjectRules.filter(r => this.isAssignment(r)).map(r => r.V1);
			const visited = new Set<string>(queue);
			for (let i = 0; i < queue.length; i++) {
				const role = queue[i];
				if (grantees.has(role)) {
					return true;
				}
				for (const parent of parents.get(role) ?? []) {
					if (!visited.has(parent)) {
						visited.add(parent);
						queue.push(parent);
					}
				}
			}

			return false;
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				CasbinAuthorizationConnector.CLASS_NAME,
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
		this.guardModelId(modelId);
		this.guardNoSeparator(nameof(subject), subject);
		this.guardNoSeparator(nameof(object), object);
		this.guardNoSeparator(nameof(action), action);

		try {
			const tenantId = await this.getTenantId();
			await this.ensureEnforcer(tenantId, modelId);
			await this.postRule(
				tenantId,
				modelId,
				"add-policy",
				{ ptype: "p", v0: subject, v1: object, v2: action },
				"addPolicyFailed",
				{ subject }
			);
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				CasbinAuthorizationConnector.CLASS_NAME,
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
		this.guardModelId(modelId);
		this.guardNoSeparator(nameof(subject), subject);
		this.guardNoSeparator(nameof(object), object);
		this.guardNoSeparator(nameof(action), action);

		try {
			const tenantId = await this.getTenantId();
			if (!(await this.enforcerExists(tenantId, modelId))) {
				return;
			}
			await this.postRule(
				tenantId,
				modelId,
				"remove-policy",
				{ ptype: "p", v0: subject, v1: object, v2: action },
				"removePolicyFailed",
				{ subject }
			);
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				CasbinAuthorizationConnector.CLASS_NAME,
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
		this.guardModelId(modelId);
		this.guardNoSeparator(nameof(subject), subject);

		return this.getAllPolicies(modelId, subject, cursor, limit);
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
		this.guardModelId(modelId);
		if (subject !== undefined) {
			this.guardNoSeparator(nameof(subject), subject);
		}
		this.guardPaging(cursor, limit);

		try {
			const tenantId = await this.getTenantId();
			if (!(await this.enforcerExists(tenantId, modelId))) {
				return { entities: [] };
			}

			const rules =
				subject === undefined
					? await this.getRules(tenantId, modelId)
					: await this.getRules(tenantId, modelId, "p", 0, [subject]);

			const policies = rules
				.filter(r => r.Ptype === "p" && (subject === undefined || r.V0 === subject))
				.map(r => ({ subject: r.V0, object: r.V1, action: r.V2 }))
				.sort(
					(a, b) =>
						a.subject.localeCompare(b.subject) ||
						a.object.localeCompare(b.object) ||
						a.action.localeCompare(b.action)
				);

			const page = this.paginate(policies, cursor, limit);
			return { entities: page.items, cursor: page.cursor };
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				CasbinAuthorizationConnector.CLASS_NAME,
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
		this.guardModelId(modelId);
		this.guardPaging(cursor, limit);

		try {
			const roleNames = await this.getRoleNames(modelId);
			const page = this.paginate(Array.from(roleNames).sort(), cursor, limit);
			return { roles: page.items, cursor: page.cursor };
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				CasbinAuthorizationConnector.CLASS_NAME,
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
		this.guardModelId(modelId);
		Guards.array<string>(CasbinAuthorizationConnector.CLASS_NAME, nameof(roles), roles);
		for (const role of roles) {
			this.guardNoSeparator(nameof(role), role);
		}

		try {
			const roleNames = await this.getRoleNames(modelId);
			return roles.map(role => roleNames.has(role));
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				CasbinAuthorizationConnector.CLASS_NAME,
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
		this.guardModelId(modelId);
		this.guardNoSeparator(nameof(subject), subject);
		this.guardNoSeparator(nameof(role), role);

		try {
			const tenantId = await this.getTenantId();
			await this.ensureEnforcer(tenantId, modelId);
			await this.postRule(
				tenantId,
				modelId,
				"add-policy",
				{ ptype: "g", v0: subject, v1: role, v2: CasbinAuthorizationConnector._ASSIGNMENT_MARKER },
				"addRoleForSubjectFailed",
				{ subject, role }
			);
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				CasbinAuthorizationConnector.CLASS_NAME,
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
		this.guardModelId(modelId);
		this.guardNoSeparator(nameof(subject), subject);
		this.guardNoSeparator(nameof(role), role);

		try {
			const tenantId = await this.getTenantId();
			if (!(await this.enforcerExists(tenantId, modelId))) {
				return;
			}
			await this.postRule(
				tenantId,
				modelId,
				"remove-policy",
				{ ptype: "g", v0: subject, v1: role, v2: CasbinAuthorizationConnector._ASSIGNMENT_MARKER },
				"removeRoleForSubjectFailed",
				{ subject, role }
			);
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				CasbinAuthorizationConnector.CLASS_NAME,
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
		this.guardModelId(modelId);
		this.guardNoSeparator(nameof(subject), subject);

		try {
			const tenantId = await this.getTenantId();
			if (!(await this.enforcerExists(tenantId, modelId))) {
				return;
			}
			const rules = await this.getRules(tenantId, modelId, "g", 0, [subject]);
			// Casdoor has no batch remove endpoint and stalls on concurrent writes, so remove sequentially.
			for (const r of rules.filter(rule => this.isAssignment(rule) && rule.V0 === subject)) {
				await this.postRule(
					tenantId,
					modelId,
					"remove-policy",
					{
						ptype: "g",
						v0: subject,
						v1: r.V1,
						v2: CasbinAuthorizationConnector._ASSIGNMENT_MARKER
					},
					"removeAllRolesForSubjectFailed",
					{ subject }
				);
			}
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				CasbinAuthorizationConnector.CLASS_NAME,
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
		this.guardModelId(modelId);
		this.guardNoSeparator(nameof(subject), subject);

		try {
			const rules = await this.getGroupingRules(modelId, 0, subject, false);
			return rules.map(r => r.V1);
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				CasbinAuthorizationConnector.CLASS_NAME,
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
		this.guardModelId(modelId);
		this.guardNoSeparator(nameof(role), role);

		try {
			const rules = await this.getGroupingRules(modelId, 1, role, false);
			return rules.map(r => r.V0);
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				CasbinAuthorizationConnector.CLASS_NAME,
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
		this.guardModelId(modelId);
		this.guardNoSeparator(nameof(subject), subject);
		this.guardNoSeparator(nameof(role), role);

		try {
			const rules = await this.getGroupingRules(modelId, 0, subject, false);
			return rules.some(r => r.V1 === role);
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				CasbinAuthorizationConnector.CLASS_NAME,
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
		this.guardModelId(modelId);
		this.guardNoSeparator(nameof(role), role);
		this.guardNoSeparator(nameof(inheritsFrom), inheritsFrom);

		try {
			const tenantId = await this.getTenantId();
			await this.ensureEnforcer(tenantId, modelId);
			await this.postRule(
				tenantId,
				modelId,
				"add-policy",
				{
					ptype: "g",
					v0: role,
					v1: inheritsFrom,
					v2: CasbinAuthorizationConnector._INHERITANCE_MARKER
				},
				"addRoleInheritanceFailed",
				{ role, inheritsFrom }
			);
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				CasbinAuthorizationConnector.CLASS_NAME,
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
		this.guardModelId(modelId);
		this.guardNoSeparator(nameof(role), role);
		this.guardNoSeparator(nameof(inheritsFrom), inheritsFrom);

		try {
			const tenantId = await this.getTenantId();
			if (!(await this.enforcerExists(tenantId, modelId))) {
				return;
			}
			await this.postRule(
				tenantId,
				modelId,
				"remove-policy",
				{
					ptype: "g",
					v0: role,
					v1: inheritsFrom,
					v2: CasbinAuthorizationConnector._INHERITANCE_MARKER
				},
				"removeRoleInheritanceFailed",
				{ role, inheritsFrom }
			);
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				CasbinAuthorizationConnector.CLASS_NAME,
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
		this.guardModelId(modelId);
		this.guardNoSeparator(nameof(role), role);

		try {
			const rules = await this.getGroupingRules(modelId, 0, role, true);
			return rules.map(r => r.V1);
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				CasbinAuthorizationConnector.CLASS_NAME,
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
		this.guardModelId(modelId);
		this.guardNoSeparator(nameof(role), role);

		try {
			const rules = await this.getGroupingRules(modelId, 1, role, true);
			return rules.map(r => r.V0);
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				CasbinAuthorizationConnector.CLASS_NAME,
				"getChildRolesFailed",
				{ role },
				err
			);
		}
	}

	/**
	 * Get the tenant ID from the ambient context, falling back to "root" as the authorization service does.
	 * @returns The tenant ID.
	 * @internal
	 */
	private async getTenantId(): Promise<string> {
		const contextIds = await ContextIdStore.getContextIds();
		const tenantId = contextIds?.[ContextIdKeys.Tenant];
		if (!Is.stringValue(tenantId)) {
			return "root";
		}
		this.guardNoPathSeparator("tenantId", tenantId);
		return tenantId;
	}

	/**
	 * Get the Casdoor enforcer ID for the tenant and model.
	 * @param tenantId The tenant ID.
	 * @param modelId The model identifier.
	 * @returns The enforcer ID in the form owner/name.
	 * @internal
	 */
	private getEnforcerId(tenantId: string, modelId: string): string {
		return `${tenantId}/${modelId}`;
	}

	/**
	 * Check whether the Casdoor enforcer exists for the tenant and model, without creating it.
	 * @param tenantId The tenant ID.
	 * @param modelId The model identifier.
	 * @returns True if the enforcer exists.
	 * @internal
	 */
	private async enforcerExists(tenantId: string, modelId: string): Promise<boolean> {
		const enforcerId = this.getEnforcerId(tenantId, modelId);
		if (this._provisionedEnforcers.has(enforcerId)) {
			return true;
		}

		const response = await FetchHelper.fetchJson<
			never,
			ICasbinServerResponse<{ owner: string } | null>
		>(
			CasbinAuthorizationConnector.CLASS_NAME,
			`${this._baseUrl}/api/get-enforcer?id=${encodeURIComponent(enforcerId)}`,
			HttpMethod.GET,
			undefined,
			this._requestOptions
		);
		if (response.status !== "ok") {
			throw new GeneralError(CasbinAuthorizationConnector.CLASS_NAME, "getEnforcerFailed", {
				enforcerId,
				serverMsg: response.msg
			});
		}
		if (response.data === null) {
			return false;
		}
		this._provisionedEnforcers.add(enforcerId);
		return true;
	}

	/**
	 * Ensure that a Casdoor enforcer exists for the tenant and model, creating it if necessary.
	 * Concurrent calls for the same enforcer are serialised so it is only provisioned once.
	 * @param tenantId The tenant ID.
	 * @param modelId The model identifier.
	 * @internal
	 */
	private async ensureEnforcer(tenantId: string, modelId: string): Promise<void> {
		const enforcerId = this.getEnforcerId(tenantId, modelId);
		if (this._provisionedEnforcers.has(enforcerId)) {
			return;
		}

		const lockKey = `${CasbinAuthorizationConnector.CLASS_NAME}/${enforcerId}`;
		await Mutex.lock(lockKey, { throwOnTimeout: true });
		try {
			await this.provisionEnforcer(tenantId, modelId);
		} finally {
			Mutex.unlock(lockKey);
		}
	}

	/**
	 * Create the tenant model, adapter and enforcer for the tenant and model if they do not already exist.
	 * @param tenantId The tenant ID.
	 * @param modelId The model identifier.
	 * @internal
	 */
	private async provisionEnforcer(tenantId: string, modelId: string): Promise<void> {
		if (await this.enforcerExists(tenantId, modelId)) {
			return;
		}

		const enforcerId = this.getEnforcerId(tenantId, modelId);
		const assertProvisioned = (response: ICasbinServerResponse<unknown>): void => {
			if (response.status !== "ok") {
				throw new GeneralError(CasbinAuthorizationConnector.CLASS_NAME, "ensureEnforcerFailed", {
					enforcerId,
					serverMsg: response.msg
				});
			}
		};
		// The model is owned by the tenant so it is not shared with, or changeable by, other tenants.
		const casdoorModelName = CasbinAuthorizationConnector._CASDOOR_MODEL_NAME;
		const casdoorModelId = `${tenantId}/${casdoorModelName}`;
		const assertModel = (response: ICasbinServerResponse<unknown>): void => {
			if (response.status !== "ok") {
				throw new GeneralError(CasbinAuthorizationConnector.CLASS_NAME, "ensureModelFailed", {
					modelId: casdoorModelId,
					serverMsg: response.msg
				});
			}
		};
		const modelResponse = await FetchHelper.fetchJson<
			never,
			ICasbinServerResponse<{ owner: string; name: string } | null>
		>(
			CasbinAuthorizationConnector.CLASS_NAME,
			`${this._baseUrl}/api/get-model?id=${encodeURIComponent(casdoorModelId)}`,
			HttpMethod.GET,
			undefined,
			this._requestOptions
		);
		assertModel(modelResponse);

		if (modelResponse.data === null) {
			const addModelResponse = await FetchHelper.fetchJson<
				{ owner: string; name: string; displayName: string; modelText: string },
				ICasbinServerResponse<unknown>
			>(
				CasbinAuthorizationConnector.CLASS_NAME,
				`${this._baseUrl}/api/add-model`,
				HttpMethod.POST,
				{
					owner: tenantId,
					name: casdoorModelName,
					displayName: casdoorModelName,
					// The third "g" field holds the assignment or inheritance marker. Roles are resolved
					// by this connector, so the matcher is not used for decisions.
					modelText: `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = (r.sub == p.sub || g(r.sub, p.sub, "${CasbinAuthorizationConnector._ASSIGNMENT_MARKER}")) && r.obj == p.obj && r.act == p.act`
				},
				this._requestOptions
			);
			assertModel(addModelResponse);
		}

		// The adapter is owned by the tenant, so its name only needs to be unique per model.
		const adapterName = `adapter-${tenantId}-${modelId}`;
		const adapterId = `${tenantId}/${adapterName}`;
		const adapterResponse = await FetchHelper.fetchJson<
			never,
			ICasbinServerResponse<{ owner: string } | null>
		>(
			CasbinAuthorizationConnector.CLASS_NAME,
			`${this._baseUrl}/api/get-adapter?id=${encodeURIComponent(adapterId)}`,
			HttpMethod.GET,
			undefined,
			this._requestOptions
		);
		assertProvisioned(adapterResponse);

		if (adapterResponse.data === null) {
			// Hash the full enforcer ID so table names cannot collide across tenants or models.
			const tableName = `casbin_${Converter.bytesToHex(Sha256.sum256(Converter.utf8ToBytes(enforcerId))).slice(0, 40)}`;
			const addAdapterResponse = await FetchHelper.fetchJson<
				{ owner: string; name: string; table: string; useSameDb: boolean },
				ICasbinServerResponse<unknown>
			>(
				CasbinAuthorizationConnector.CLASS_NAME,
				`${this._baseUrl}/api/add-adapter`,
				HttpMethod.POST,
				{ owner: tenantId, name: adapterName, table: tableName, useSameDb: true },
				this._requestOptions
			);
			assertProvisioned(addAdapterResponse);
		}

		const addEnforcerResponse = await FetchHelper.fetchJson<
			{ owner: string; name: string; model: string; adapter: string; isEnabled: boolean },
			ICasbinServerResponse<unknown>
		>(
			CasbinAuthorizationConnector.CLASS_NAME,
			`${this._baseUrl}/api/add-enforcer`,
			HttpMethod.POST,
			{
				owner: tenantId,
				name: modelId,
				model: casdoorModelId,
				adapter: adapterId,
				isEnabled: true
			},
			this._requestOptions
		);
		assertProvisioned(addEnforcerResponse);

		this._provisionedEnforcers.add(enforcerId);
	}

	/**
	 * Fetch policy rules from an existing enforcer, optionally filtered on consecutive fields.
	 * @param tenantId The tenant ID.
	 * @param modelId The model identifier.
	 * @param ptype The policy type to filter on.
	 * @param fieldIndex The index of the first field to filter on.
	 * @param fieldValues The values the fields must match, starting at fieldIndex.
	 * @returns The matching rules.
	 * @internal
	 */
	private async getRules(
		tenantId: string,
		modelId: string,
		ptype?: string,
		fieldIndex?: number,
		fieldValues?: string[]
	): Promise<ICasdoorPolicyRule[]> {
		const encodedEnforcerId = encodeURIComponent(this.getEnforcerId(tenantId, modelId));
		const response =
			ptype === undefined
				? await FetchHelper.fetchJson<never, ICasbinServerResponse<ICasdoorPolicyRule[] | null>>(
						CasbinAuthorizationConnector.CLASS_NAME,
						`${this._baseUrl}/api/get-policies?id=${encodedEnforcerId}`,
						HttpMethod.GET,
						undefined,
						this._requestOptions
					)
				: await FetchHelper.fetchJson<
						{ ptype: string; fieldIndex?: number; fieldValues?: string[] }[],
						ICasbinServerResponse<ICasdoorPolicyRule[] | null>
					>(
						CasbinAuthorizationConnector.CLASS_NAME,
						`${this._baseUrl}/api/get-filtered-policies?id=${encodedEnforcerId}`,
						HttpMethod.POST,
						[{ ptype, fieldIndex, fieldValues }],
						this._requestOptions
					);

		this.assertOk(response, "getAllPoliciesFailed");
		return (response.data ?? []).filter(r => ptype === undefined || r.Ptype === ptype);
	}

	/**
	 * Get the role assignment or inheritance rules where the given field matches the value.
	 * @param modelId The model identifier.
	 * @param fieldIndex 0 to match V0, 1 to match V1.
	 * @param value The value to match.
	 * @param inheritance True for inheritance rules, false for assignment rules.
	 * @returns The matching rules.
	 * @internal
	 */
	private async getGroupingRules(
		modelId: string,
		fieldIndex: 0 | 1,
		value: string,
		inheritance: boolean
	): Promise<ICasdoorPolicyRule[]> {
		const tenantId = await this.getTenantId();
		if (!(await this.enforcerExists(tenantId, modelId))) {
			return [];
		}
		const rules = await this.getRules(tenantId, modelId, "g", fieldIndex, [value]);
		return rules.filter(
			r =>
				(fieldIndex === 0 ? r.V0 : r.V1) === value &&
				(inheritance ? this.isInheritance(r) : this.isAssignment(r))
		);
	}

	/**
	 * Get the distinct role names: roles assigned to subjects and roles inherited from.
	 * @param modelId The model identifier.
	 * @returns The role names.
	 * @internal
	 */
	private async getRoleNames(modelId: string): Promise<Set<string>> {
		const tenantId = await this.getTenantId();
		if (!(await this.enforcerExists(tenantId, modelId))) {
			return new Set<string>();
		}
		// Filtering on all "g" rows is not reliable through the Casdoor filter API, so fetch all.
		const rules = await this.getRules(tenantId, modelId);
		return new Set(rules.filter(r => r.Ptype === "g").map(r => r.V1));
	}

	/**
	 * Post a single rule to an add or remove endpoint.
	 * @param tenantId The tenant ID.
	 * @param modelId The model identifier.
	 * @param endpoint The endpoint name.
	 * @param rule The rule to post.
	 * @param errorKey The i18n error key to use on failure.
	 * @param properties Additional properties for the error.
	 * @internal
	 */
	private async postRule(
		tenantId: string,
		modelId: string,
		endpoint: "add-policy" | "remove-policy",
		rule: { [key: string]: string },
		errorKey: string,
		properties: { [key: string]: unknown }
	): Promise<void> {
		const encodedEnforcerId = encodeURIComponent(this.getEnforcerId(tenantId, modelId));
		const response = await FetchHelper.fetchJson<
			{ [key: string]: string },
			ICasbinServerResponse<string>
		>(
			CasbinAuthorizationConnector.CLASS_NAME,
			`${this._baseUrl}/api/${endpoint}?id=${encodedEnforcerId}`,
			HttpMethod.POST,
			rule,
			this._requestOptions
		);
		this.assertOk(response, errorKey, properties);
	}

	/**
	 * Is the rule a role assignment.
	 * @param rule The rule.
	 * @returns True if the rule is a role assignment.
	 * @internal
	 */
	private isAssignment(rule: ICasdoorPolicyRule): boolean {
		return rule.Ptype === "g" && rule.V2 === CasbinAuthorizationConnector._ASSIGNMENT_MARKER;
	}

	/**
	 * Is the rule a role inheritance.
	 * @param rule The rule.
	 * @returns True if the rule is a role inheritance.
	 * @internal
	 */
	private isInheritance(rule: ICasdoorPolicyRule): boolean {
		return rule.Ptype === "g" && rule.V2 === CasbinAuthorizationConnector._INHERITANCE_MARKER;
	}

	/**
	 * Slice a sorted list into a page using an offset cursor.
	 * @param items The sorted items.
	 * @param cursor The offset cursor.
	 * @param limit The page size.
	 * @returns The page and the cursor for the next page.
	 * @internal
	 */
	private paginate<T>(
		items: T[],
		cursor?: string,
		limit?: number
	): { items: T[]; cursor?: string } {
		const offset = cursor === undefined ? 0 : Number.parseInt(cursor, 10);
		const pageSize = limit ?? CasbinAuthorizationConnector._DEFAULT_PAGE_SIZE;
		const nextOffset = offset + pageSize;
		return {
			items: items.slice(offset, nextOffset),
			cursor: nextOffset < items.length ? String(nextOffset) : undefined
		};
	}

	/**
	 * Validate the paging parameters.
	 * @param cursor The cursor, which must be a non-negative integer string.
	 * @param limit The limit, which must be a positive integer.
	 * @throws GuardError if either value is invalid.
	 * @internal
	 */
	private guardPaging(cursor?: string, limit?: number): void {
		if (cursor !== undefined && !/^\d+$/.test(cursor)) {
			throw new GuardError(
				CasbinAuthorizationConnector.CLASS_NAME,
				"invalidCursor",
				nameof(cursor),
				cursor
			);
		}
		if (limit !== undefined && (!Is.integer(limit) || limit <= 0)) {
			throw new GuardError(
				CasbinAuthorizationConnector.CLASS_NAME,
				"invalidLimit",
				nameof(limit),
				limit
			);
		}
	}

	/**
	 * Assert that a server response has status "ok", throwing a GeneralError otherwise.
	 * @param response The server response envelope.
	 * @param errorKey The i18n error key to use if the response is not ok.
	 * @param properties Additional properties for the error.
	 * @throws GeneralError if the response status is not "ok".
	 * @internal
	 */
	private assertOk<T>(
		response: ICasbinServerResponse<T>,
		errorKey: string,
		properties?: { [key: string]: unknown }
	): void {
		if (response.status !== "ok") {
			throw new GeneralError(CasbinAuthorizationConnector.CLASS_NAME, errorKey, {
				...properties,
				serverMsg: response.msg
			});
		}
	}

	/**
	 * Validate a model identifier, which is used as a Casdoor enforcer name.
	 * @param modelId The model identifier.
	 * @throws GeneralError If the value contains a "|" or "/" character.
	 * @internal
	 */
	private guardModelId(modelId: string): void {
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoPathSeparator(nameof(modelId), modelId);
	}

	/**
	 * Throw a GeneralError if the value contains the pipe separator character.
	 * @param fieldName The field name for the error context.
	 * @param value The value to validate.
	 * @throws GeneralError If the value contains a pipe character.
	 * @internal
	 */
	private guardNoSeparator(fieldName: string, value: string): void {
		Guards.stringValue(CasbinAuthorizationConnector.CLASS_NAME, fieldName, value);
		if (value.includes("|")) {
			throw new GeneralError(CasbinAuthorizationConnector.CLASS_NAME, "containsSeparator", {
				fieldName
			});
		}
	}

	/**
	 * Throw a GeneralError if the value contains a "/", as Casdoor uses it to separate owner and name.
	 * @param fieldName The field name for the error context.
	 * @param value The value to validate.
	 * @throws GeneralError If the value contains a "/" character.
	 * @internal
	 */
	private guardNoPathSeparator(fieldName: string, value: string): void {
		if (value.includes("/")) {
			throw new GeneralError(CasbinAuthorizationConnector.CLASS_NAME, "containsPathSeparator", {
				fieldName
			});
		}
	}
}
