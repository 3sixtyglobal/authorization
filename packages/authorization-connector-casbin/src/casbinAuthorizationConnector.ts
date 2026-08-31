// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type {
	IAuthorizationConnector,
	IAuthorizationModel,
	IAuthorizationPolicy
} from "@twin.org/authorization-models";
import { ContextIdKeys, ContextIdStore } from "@twin.org/context";
import {
	BaseError,
	ComponentFactory,
	Converter,
	GeneralError,
	Guards,
	Is,
	StringHelper
} from "@twin.org/core";
import type { ILoggingComponent } from "@twin.org/logging-models";
import { nameof } from "@twin.org/nameof";
import { FetchHelper, HttpMethod, type IHttpHeaders } from "@twin.org/web";
import type { ICasbinAuthorizationConnectorConfig } from "./models/ICasbinAuthorizationConnectorConfig.js";
import type { ICasbinAuthorizationConnectorConstructorOptions } from "./models/ICasbinAuthorizationConnectorConstructorOptions.js";
import type { ICasbinServerResponse } from "./models/ICasbinServerResponse.js";
import type { ICasdoorPolicyRule } from "./models/ICasdoorPolicyRule.js";

/**
 * A connector that implements the IAuthorizationConnector interface using the Casbin server REST API.
 *
 * Tenant separation is physical: each tenant gets its own enforcer and policy table.
 * Organization scoping rides on the rules themselves via the ambient organization context id:
 * writes stamp the current organization (the last value slot of each rule), checks and queries
 * match rules whose organization is empty (global) or equals the current organization, and
 * removals target the current organization exactly.
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
				CasbinAuthorizationConnector.CLASS_NAME,
				"buildFailed",
				undefined,
				err
			);
		}
	}

	/**
	 * Check whether a subject is permitted to perform an action on an object.
	 * Evaluates RBAC locally by traversing role inheritance from the stored grouping policies.
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
			const organizationId = await this.getOrganizationId();
			const allRules = await this.getAllRawPolicies(modelId);

			const permissions = allRules.filter(
				r => r.Ptype === "p" && this.organizationMatches(r.V3, organizationId)
			);
			const groupings = allRules.filter(
				r => r.Ptype === "g" && this.organizationMatches(r.V2, organizationId)
			);

			const roleGraph = new Map<string, Set<string>>();
			for (const g of groupings) {
				if (!roleGraph.has(g.V0)) {
					roleGraph.set(g.V0, new Set());
				}
				roleGraph.get(g.V0)?.add(g.V1);
			}

			const reachable = new Set<string>([subject]);
			const queue: string[] = [subject];
			while (queue.length > 0) {
				const current = queue.shift() ?? "";
				for (const role of roleGraph.get(current) ?? []) {
					if (!reachable.has(role)) {
						reachable.add(role);
						queue.push(role);
					}
				}
			}

			return permissions.some(p => reachable.has(p.V0) && p.V1 === object && p.V2 === action);
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
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(subject), subject);
		this.guardNoSeparator(nameof(object), object);
		this.guardNoSeparator(nameof(action), action);

		try {
			await this.ensureEnforcer(modelId);
			const organizationId = await this.getOrganizationId();
			const encodedEnforcerId = await this.getEncodedEnforcerId(modelId);
			const response = await FetchHelper.fetchJson<
				{ ptype: string; v0: string; v1: string; v2: string; v3?: string },
				ICasbinServerResponse<string>
			>(
				CasbinAuthorizationConnector.CLASS_NAME,
				`${this._baseUrl}/api/add-policy?id=${encodedEnforcerId}`,
				HttpMethod.POST,
				{
					ptype: "p",
					v0: subject,
					v1: object,
					v2: action,
					v3: Is.stringValue(organizationId) ? organizationId : undefined
				},
				this._requestOptions
			);

			this.assertOk(response, "addPolicyFailed", { subject });
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
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(subject), subject);
		this.guardNoSeparator(nameof(object), object);
		this.guardNoSeparator(nameof(action), action);

		try {
			const organizationId = await this.getOrganizationId();
			const encodedEnforcerId = await this.getEncodedEnforcerId(modelId);
			const response = await FetchHelper.fetchJson<
				{ ptype: string; v0: string; v1: string; v2: string; v3?: string },
				ICasbinServerResponse<string>
			>(
				CasbinAuthorizationConnector.CLASS_NAME,
				`${this._baseUrl}/api/remove-policy?id=${encodedEnforcerId}`,
				HttpMethod.POST,
				{
					ptype: "p",
					v0: subject,
					v1: object,
					v2: action,
					v3: Is.stringValue(organizationId) ? organizationId : undefined
				},
				this._requestOptions
			);

			this.assertOk(response, "removePolicyFailed", { subject });
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
		this.guardNoSeparator(nameof(modelId), modelId);
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
		this.guardNoSeparator(nameof(modelId), modelId);
		if (subject !== undefined) {
			this.guardNoSeparator(nameof(subject), subject);
		}

		try {
			const organizationId = await this.getOrganizationId();
			const rules = await this.getAllRawPolicies(modelId);
			let policies = rules
				.filter(r => r.Ptype === "p" && this.organizationMatches(r.V3, organizationId))
				.map(r => ({
					subject: r.V0,
					object: r.V1,
					action: r.V2,
					organization: Is.stringValue(r.V3) ? r.V3 : undefined
				}));

			if (subject !== undefined) {
				policies = policies.filter(p => p.subject === subject);
			}

			if (limit === undefined) {
				return { entities: policies };
			}

			const offset = cursor !== undefined ? parseInt(cursor, 10) : 0;
			const pagePolicies = policies.slice(offset, offset + limit);
			const nextOffset = offset + limit;

			return {
				entities: pagePolicies,
				cursor: nextOffset < policies.length ? String(nextOffset) : undefined
			};
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
		this.guardNoSeparator(nameof(modelId), modelId);

		try {
			const rules = await this.getAllRawPolicies(modelId);
			const gRules = rules.filter(rule => rule.Ptype === "g");
			const v1Set = new Set(gRules.map(r => r.V1));
			const roleSet = new Set<string>();
			for (const r of gRules) {
				roleSet.add(r.V1);
				if (v1Set.has(r.V0)) {
					roleSet.add(r.V0);
				}
			}
			const allRoles = Array.from(roleSet).sort();

			if (limit === undefined) {
				return { roles: allRoles };
			}

			const offset = cursor !== undefined ? parseInt(cursor, 10) : 0;
			const pageRoles = allRoles.slice(offset, offset + limit);
			const nextOffset = offset + limit;

			return {
				roles: pageRoles,
				cursor: nextOffset < allRoles.length ? String(nextOffset) : undefined
			};
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
		this.guardNoSeparator(nameof(modelId), modelId);
		Guards.array<string>(CasbinAuthorizationConnector.CLASS_NAME, nameof(roles), roles);
		for (const role of roles) {
			this.guardNoSeparator(nameof(role), role);
		}

		try {
			const rules = await this.getAllRawPolicies(modelId);
			const gRules = rules.filter(rule => rule.Ptype === "g");
			const v1Set = new Set(gRules.map(r => r.V1));
			const roleSet = new Set<string>();
			for (const r of gRules) {
				roleSet.add(r.V1);
				if (v1Set.has(r.V0)) {
					roleSet.add(r.V0);
				}
			}
			return roles.map(role => roleSet.has(role));
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
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(subject), subject);
		this.guardNoSeparator(nameof(role), role);

		try {
			await this.ensureEnforcer(modelId);
			const organizationId = await this.getOrganizationId();
			const encodedEnforcerId = await this.getEncodedEnforcerId(modelId);
			const response = await FetchHelper.fetchJson<
				{ ptype: string; v0: string; v1: string; v2?: string },
				ICasbinServerResponse<string>
			>(
				CasbinAuthorizationConnector.CLASS_NAME,
				`${this._baseUrl}/api/add-policy?id=${encodedEnforcerId}`,
				HttpMethod.POST,
				{
					ptype: "g",
					v0: subject,
					v1: role,
					v2: Is.stringValue(organizationId) ? organizationId : undefined
				},
				this._requestOptions
			);

			this.assertOk(response, "addRoleForSubjectFailed", { subject, role });
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
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(subject), subject);
		this.guardNoSeparator(nameof(role), role);

		try {
			const organizationId = await this.getOrganizationId();
			const encodedEnforcerId = await this.getEncodedEnforcerId(modelId);
			const response = await FetchHelper.fetchJson<
				{ ptype: string; v0: string; v1: string; v2?: string },
				ICasbinServerResponse<string>
			>(
				CasbinAuthorizationConnector.CLASS_NAME,
				`${this._baseUrl}/api/remove-policy?id=${encodedEnforcerId}`,
				HttpMethod.POST,
				{
					ptype: "g",
					v0: subject,
					v1: role,
					v2: Is.stringValue(organizationId) ? organizationId : undefined
				},
				this._requestOptions
			);

			this.assertOk(response, "removeRoleForSubjectFailed", { subject, role });
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
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(subject), subject);

		try {
			const organizationId = await this.getOrganizationId();
			const rules = await this.getAllRawPolicies(modelId);
			const subjectRoles = rules.filter(
				r =>
					r.Ptype === "g" &&
					r.V0 === subject &&
					(Is.stringValue(r.V2) ? r.V2 : undefined) === organizationId
			);
			for (const rule of subjectRoles) {
				await this.removeRoleForSubject(modelId, subject, rule.V1);
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
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(subject), subject);

		try {
			const organizationId = await this.getOrganizationId();
			const rules = await this.getAllRawPolicies(modelId);
			return Array.from(
				new Set(
					rules
						.filter(
							r =>
								r.Ptype === "g" &&
								r.V0 === subject &&
								this.organizationMatches(r.V2, organizationId)
						)
						.map(r => r.V1)
				)
			);
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
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(role), role);

		try {
			const organizationId = await this.getOrganizationId();
			const rules = await this.getAllRawPolicies(modelId);
			return Array.from(
				new Set(
					rules
						.filter(
							r =>
								r.Ptype === "g" && r.V1 === role && this.organizationMatches(r.V2, organizationId)
						)
						.map(r => r.V0)
				)
			);
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
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(subject), subject);
		this.guardNoSeparator(nameof(role), role);

		try {
			const organizationId = await this.getOrganizationId();
			const rules = await this.getAllRawPolicies(modelId);
			return rules.some(
				r =>
					r.Ptype === "g" &&
					r.V0 === subject &&
					r.V1 === role &&
					this.organizationMatches(r.V2, organizationId)
			);
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
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(role), role);
		this.guardNoSeparator(nameof(inheritsFrom), inheritsFrom);

		try {
			await this.ensureEnforcer(modelId);
			const organizationId = await this.getOrganizationId();
			const encodedEnforcerId = await this.getEncodedEnforcerId(modelId);
			const response = await FetchHelper.fetchJson<
				{ ptype: string; v0: string; v1: string; v2?: string },
				ICasbinServerResponse<string>
			>(
				CasbinAuthorizationConnector.CLASS_NAME,
				`${this._baseUrl}/api/add-policy?id=${encodedEnforcerId}`,
				HttpMethod.POST,
				{
					ptype: "g",
					v0: role,
					v1: inheritsFrom,
					v2: Is.stringValue(organizationId) ? organizationId : undefined
				},
				this._requestOptions
			);

			this.assertOk(response, "addRoleInheritanceFailed", { role, inheritsFrom });
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
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(role), role);
		this.guardNoSeparator(nameof(inheritsFrom), inheritsFrom);

		try {
			const organizationId = await this.getOrganizationId();
			const encodedEnforcerId = await this.getEncodedEnforcerId(modelId);
			const response = await FetchHelper.fetchJson<
				{ ptype: string; v0: string; v1: string; v2?: string },
				ICasbinServerResponse<string>
			>(
				CasbinAuthorizationConnector.CLASS_NAME,
				`${this._baseUrl}/api/remove-policy?id=${encodedEnforcerId}`,
				HttpMethod.POST,
				{
					ptype: "g",
					v0: role,
					v1: inheritsFrom,
					v2: Is.stringValue(organizationId) ? organizationId : undefined
				},
				this._requestOptions
			);

			this.assertOk(response, "removeRoleInheritanceFailed", { role, inheritsFrom });
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
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(role), role);

		try {
			const organizationId = await this.getOrganizationId();
			const rules = await this.getAllRawPolicies(modelId);
			return Array.from(
				new Set(
					rules
						.filter(
							r =>
								r.Ptype === "g" && r.V0 === role && this.organizationMatches(r.V2, organizationId)
						)
						.map(r => r.V1)
				)
			);
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
		this.guardNoSeparator(nameof(modelId), modelId);
		this.guardNoSeparator(nameof(role), role);

		try {
			const organizationId = await this.getOrganizationId();
			const rules = await this.getAllRawPolicies(modelId);
			return Array.from(
				new Set(
					rules
						.filter(
							r =>
								r.Ptype === "g" && r.V1 === role && this.organizationMatches(r.V2, organizationId)
						)
						.map(r => r.V0)
				)
			);
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
	 * Get the URL-encoded enforcer ID from the ambient tenant context and the given model identifier.
	 * @param modelId The model identifier.
	 * @param encode Whether to URL-encode the result (default: true).
	 * @returns The URL-encoded enforcer ID in the form owner/modelId.
	 * @internal
	 */
	private async getEncodedEnforcerId(modelId: string, encode?: boolean): Promise<string> {
		const tenantId = await this.getTenantId();
		const enforcerId = `${tenantId}/${modelId}`;
		return encode === false ? enforcerId : encodeURIComponent(enforcerId);
	}

	/**
	 * Get the tenant ID from the ambient context.
	 * @returns The tenant ID.
	 * @internal
	 */
	private async getTenantId(): Promise<string> {
		const contextIds = await ContextIdStore.getContextIds();
		const tenantId = contextIds?.[ContextIdKeys.Tenant];
		return Is.stringValue(tenantId) ? tenantId : "root";
	}

	/**
	 * Get the organization ID from the ambient context, following the user organization
	 * when present and falling back to the deployment organization, matching the convention
	 * used by other TWIN services.
	 * @returns The organization ID, or undefined for the global scope.
	 * @internal
	 */
	private async getOrganizationId(): Promise<string | undefined> {
		const contextIds = await ContextIdStore.getContextIds();
		const organizationId =
			contextIds?.[ContextIdKeys.UserOrganization] ?? contextIds?.[ContextIdKeys.Organization];
		return Is.stringValue(organizationId) ? organizationId : undefined;
	}

	/**
	 * Check whether a rule's organization value is visible in the given organization scope:
	 * an empty value is a global rule and always matches, otherwise the values must be equal.
	 * @param ruleOrganization The organization value stored on the rule.
	 * @param organizationId The current organization scope, undefined for global.
	 * @returns True if the rule is visible.
	 * @internal
	 */
	private organizationMatches(
		ruleOrganization: string | undefined,
		organizationId: string | undefined
	): boolean {
		return !Is.stringValue(ruleOrganization) || ruleOrganization === organizationId;
	}

	/**
	 * Ensure that a Casdoor enforcer exists for the current tenant and model.
	 * Checks that the shared RBAC model exists and creates a dedicated adapter and enforcer if
	 * the tenant-specific enforcer does not exist.
	 * @param modelId The model identifier (used as the enforcer name within the tenant owner).
	 * @internal
	 */
	private async ensureEnforcer(modelId: string): Promise<void> {
		const enforcerId = await this.getEncodedEnforcerId(modelId, false);
		if (this._provisionedEnforcers.has(enforcerId)) {
			return;
		}

		const checkResponse = await FetchHelper.fetchJson<
			never,
			ICasbinServerResponse<{ owner: string } | null>
		>(
			CasbinAuthorizationConnector.CLASS_NAME,
			`${this._baseUrl}/api/get-enforcer?id=${encodeURIComponent(enforcerId)}`,
			HttpMethod.GET,
			undefined,
			this._requestOptions
		);

		if (checkResponse.status === "ok" && checkResponse.data !== null) {
			this._provisionedEnforcers.add(enforcerId);
			return;
		}

		const tenantId = await this.getTenantId();
		const name = modelId;
		const tenantName = `${tenantId}-${name}`;
		const adapterName = `adapter-${tenantName}`;
		const tableName = `casbin_${tenantName.replace(/[^a-zA-Z0-9]/g, "_")}`;
		const casdoorModelId = "built-in/user-model-built-in";
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

		if (modelResponse.status !== "ok" || modelResponse.data === null) {
			throw new GeneralError(CasbinAuthorizationConnector.CLASS_NAME, "ensureModelFailed", {
				modelId: casdoorModelId,
				serverMsg: modelResponse.msg
			});
		}

		await FetchHelper.fetchJson<
			{ owner: string; name: string; table: string; useSameDb: boolean },
			ICasbinServerResponse<null>
		>(
			CasbinAuthorizationConnector.CLASS_NAME,
			`${this._baseUrl}/api/add-adapter`,
			HttpMethod.POST,
			{ owner: tenantId, name: adapterName, table: tableName, useSameDb: true },
			this._requestOptions
		);

		await FetchHelper.fetchJson<
			{ owner: string; name: string; model: string; adapter: string; isEnabled: boolean },
			ICasbinServerResponse<null>
		>(
			CasbinAuthorizationConnector.CLASS_NAME,
			`${this._baseUrl}/api/add-enforcer`,
			HttpMethod.POST,
			{
				owner: tenantId,
				name,
				model: casdoorModelId,
				adapter: `${tenantId}/${adapterName}`,
				isEnabled: true
			},
			this._requestOptions
		);

		this._provisionedEnforcers.add(enforcerId);
	}

	/**
	 * Fetch all raw policy rules from the Casdoor enforcer for the given model.
	 * @param modelId The model identifier.
	 * @returns All rules (both "p" permission and "g" grouping types).
	 * @internal
	 */
	private async getAllRawPolicies(modelId: string): Promise<ICasdoorPolicyRule[]> {
		await this.ensureEnforcer(modelId);

		const encodedEnforcerId = await this.getEncodedEnforcerId(modelId);
		const response = await FetchHelper.fetchJson<
			never,
			ICasbinServerResponse<ICasdoorPolicyRule[]>
		>(
			CasbinAuthorizationConnector.CLASS_NAME,
			`${this._baseUrl}/api/get-policies?id=${encodedEnforcerId}`,
			HttpMethod.GET,
			undefined,
			this._requestOptions
		);

		this.assertOk(response, "getAllPoliciesFailed");
		return response.data ?? [];
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
}
