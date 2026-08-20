// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IAuthorizationConnector, IAuthorizationPolicy } from "@twin.org/authorization-models";
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
	 * URL-encoded enforcer ID for use in query strings.
	 * @internal
	 */
	private readonly _encodedEnforcerId: string;

	/**
	 * Shared request options for every fetch call.
	 * @internal
	 */
	private readonly _requestOptions: { headers: IHttpHeaders; timeoutMs?: number };

	/**
	 * Creates a new instance of the CasbinAuthorizationConnector.
	 * @param options The options for the connector.
	 * @throws GeneralError if the enforcer ID is not in owner/name format.
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
		Guards.stringValue(
			CasbinAuthorizationConnector.CLASS_NAME,
			nameof(options.config.enforcerId),
			options.config.enforcerId
		);

		this._config = options.config;
		this._loggingComponent = ComponentFactory.getIfExists<ILoggingComponent>(
			options.loggingComponentType
		);

		this._baseUrl = StringHelper.trimTrailingSlashes(this._config.endpoint);

		const separatorIndex = this._config.enforcerId.indexOf("/");
		if (separatorIndex <= 0) {
			throw new GeneralError(CasbinAuthorizationConnector.CLASS_NAME, "invalidEnforcerId", {
				enforcerId: this._config.enforcerId
			});
		}
		this._encodedEnforcerId = encodeURIComponent(this._config.enforcerId);

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
	 * Check whether a subject is permitted to perform an action on an object.
	 * Evaluates RBAC locally by traversing role inheritance from the stored grouping policies.
	 * @param subject The subject requesting access.
	 * @param object The object being accessed.
	 * @param action The action to check.
	 * @returns True if access is granted, false otherwise.
	 * @throws GeneralError if the check request fails.
	 */
	public async check(subject: string, object: string, action: string): Promise<boolean> {
		Guards.stringValue(CasbinAuthorizationConnector.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(CasbinAuthorizationConnector.CLASS_NAME, nameof(object), object);
		Guards.stringValue(CasbinAuthorizationConnector.CLASS_NAME, nameof(action), action);

		try {
			const tenantId = await this.getTenantId();
			const prefixedSubject = this.applyTenant(tenantId, subject);
			const prefixedObject = this.applyTenant(tenantId, object);
			const allRules = await this.getAllRawPolicies();

			const permissions = allRules.filter(r => r.Ptype === "p");
			const groupings = allRules.filter(r => r.Ptype === "g");

			const roleGraph = new Map<string, Set<string>>();
			for (const g of groupings) {
				if (!roleGraph.has(g.V0)) {
					roleGraph.set(g.V0, new Set());
				}
				roleGraph.get(g.V0)?.add(g.V1);
			}

			const reachable = new Set<string>([prefixedSubject]);
			const queue: string[] = [prefixedSubject];
			while (queue.length > 0) {
				const current = queue.shift() ?? "";
				for (const role of roleGraph.get(current) ?? []) {
					if (!reachable.has(role)) {
						reachable.add(role);
						queue.push(role);
					}
				}
			}

			return permissions.some(
				p => reachable.has(p.V0) && p.V1 === prefixedObject && p.V2 === action
			);
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
	 * Check whether any of the given subjects are permitted to perform an action on a resource.
	 * Fetches all policies once and evaluates each subject locally, avoiding repeated HTTP calls.
	 * Returns one result per subject in the same order as the input array.
	 * @param subjects The subjects to check.
	 * @param object The object being accessed.
	 * @param action The action to check.
	 * @returns An array of per-subject results in input order.
	 * @throws GeneralError if the check request fails.
	 */
	public async checkAny(
		subjects: string[],
		object: string,
		action: string
	): Promise<(boolean | undefined)[]> {
		Guards.array<string>(CasbinAuthorizationConnector.CLASS_NAME, nameof(subjects), subjects);
		Guards.stringValue(CasbinAuthorizationConnector.CLASS_NAME, nameof(object), object);
		Guards.stringValue(CasbinAuthorizationConnector.CLASS_NAME, nameof(action), action);

		if (subjects.length === 0) {
			return [];
		}

		try {
			const tenantId = await this.getTenantId();
			const prefixedObject = this.applyTenant(tenantId, object);
			const allRules = await this.getAllRawPolicies();

			const permissions = allRules.filter(r => r.Ptype === "p");
			const groupings = allRules.filter(r => r.Ptype === "g");

			const roleGraph = new Map<string, Set<string>>();
			for (const g of groupings) {
				if (!roleGraph.has(g.V0)) {
					roleGraph.set(g.V0, new Set());
				}
				roleGraph.get(g.V0)?.add(g.V1);
			}

			return subjects.map(subject => {
				const prefixedSubject = this.applyTenant(tenantId, subject);
				const reachable = new Set<string>([prefixedSubject]);
				const queue: string[] = [prefixedSubject];
				while (queue.length > 0) {
					const current = queue.shift() ?? "";
					for (const role of roleGraph.get(current) ?? []) {
						if (!reachable.has(role)) {
							reachable.add(role);
							queue.push(role);
						}
					}
				}
				return permissions.some(
					p => reachable.has(p.V0) && p.V1 === prefixedObject && p.V2 === action
				);
			});
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				CasbinAuthorizationConnector.CLASS_NAME,
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
			CasbinAuthorizationConnector.CLASS_NAME,
			nameof(policy),
			policy
		);
		Guards.stringValue(
			CasbinAuthorizationConnector.CLASS_NAME,
			nameof(policy.subject),
			policy.subject
		);
		Guards.stringValue(
			CasbinAuthorizationConnector.CLASS_NAME,
			nameof(policy.object),
			policy.object
		);
		Guards.stringValue(
			CasbinAuthorizationConnector.CLASS_NAME,
			nameof(policy.action),
			policy.action
		);

		try {
			const tenantId = await this.getTenantId();
			const response = await FetchHelper.fetchJson<
				{ ptype: string; v0: string; v1: string; v2: string },
				ICasbinServerResponse<string>
			>(
				CasbinAuthorizationConnector.CLASS_NAME,
				`${this._baseUrl}/api/add-policy?id=${this._encodedEnforcerId}`,
				HttpMethod.POST,
				{
					ptype: "p",
					v0: this.applyTenant(tenantId, policy.subject),
					v1: this.applyTenant(tenantId, policy.object),
					v2: policy.action
				},
				this._requestOptions
			);

			this.assertOk(response, "addPolicyFailed", { subject: policy.subject });
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				CasbinAuthorizationConnector.CLASS_NAME,
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
			CasbinAuthorizationConnector.CLASS_NAME,
			nameof(policy),
			policy
		);
		Guards.stringValue(
			CasbinAuthorizationConnector.CLASS_NAME,
			nameof(policy.subject),
			policy.subject
		);
		Guards.stringValue(
			CasbinAuthorizationConnector.CLASS_NAME,
			nameof(policy.object),
			policy.object
		);
		Guards.stringValue(
			CasbinAuthorizationConnector.CLASS_NAME,
			nameof(policy.action),
			policy.action
		);

		try {
			const tenantId = await this.getTenantId();
			const response = await FetchHelper.fetchJson<
				{ ptype: string; v0: string; v1: string; v2: string },
				ICasbinServerResponse<string>
			>(
				CasbinAuthorizationConnector.CLASS_NAME,
				`${this._baseUrl}/api/remove-policy?id=${this._encodedEnforcerId}`,
				HttpMethod.POST,
				{
					ptype: "p",
					v0: this.applyTenant(tenantId, policy.subject),
					v1: this.applyTenant(tenantId, policy.object),
					v2: policy.action
				},
				this._requestOptions
			);

			this.assertOk(response, "removePolicyFailed", { subject: policy.subject });
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				CasbinAuthorizationConnector.CLASS_NAME,
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
		Guards.stringValue(CasbinAuthorizationConnector.CLASS_NAME, nameof(subject), subject);

		const result = await this.getAllPolicies(subject);
		return result.entities;
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
			const tenantId = await this.getTenantId();
			const rules = await this.getAllRawPolicies();
			let policies = rules
				.filter(r => r.Ptype === "p" && this.isTenantValue(tenantId, r.V0))
				.map(r => ({
					subject: this.stripTenant(tenantId, r.V0),
					object: this.stripTenant(tenantId, r.V1),
					action: r.V2
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
			const tenantId = await this.getTenantId();
			const rules = await this.getAllRawPolicies();
			const gRules = rules.filter(
				rule => rule.Ptype === "g" && this.isTenantValue(tenantId, rule.V1)
			);
			const v1Set = new Set(gRules.map(r => r.V1));
			const roleSet = new Set<string>();
			for (const r of gRules) {
				roleSet.add(this.stripTenant(tenantId, r.V1));
				if (v1Set.has(r.V0)) {
					roleSet.add(this.stripTenant(tenantId, r.V0));
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
	 * Assign a role to a subject.
	 * @param subject The subject to assign the role to.
	 * @param role The role to assign.
	 * @returns Nothing.
	 * @throws GeneralError if the request fails.
	 */
	public async addRoleForSubject(subject: string, role: string): Promise<void> {
		Guards.stringValue(CasbinAuthorizationConnector.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(CasbinAuthorizationConnector.CLASS_NAME, nameof(role), role);

		try {
			const tenantId = await this.getTenantId();
			const response = await FetchHelper.fetchJson<
				{ ptype: string; v0: string; v1: string },
				ICasbinServerResponse<string>
			>(
				CasbinAuthorizationConnector.CLASS_NAME,
				`${this._baseUrl}/api/add-policy?id=${this._encodedEnforcerId}`,
				HttpMethod.POST,
				{
					ptype: "g",
					v0: this.applyTenant(tenantId, subject),
					v1: this.applyTenant(tenantId, role)
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
	 * @param subject The subject to remove the role from.
	 * @param role The role to remove.
	 * @returns Nothing.
	 * @throws GeneralError if the request fails.
	 */
	public async removeRoleForSubject(subject: string, role: string): Promise<void> {
		Guards.stringValue(CasbinAuthorizationConnector.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(CasbinAuthorizationConnector.CLASS_NAME, nameof(role), role);

		try {
			const tenantId = await this.getTenantId();
			const response = await FetchHelper.fetchJson<
				{ ptype: string; v0: string; v1: string },
				ICasbinServerResponse<string>
			>(
				CasbinAuthorizationConnector.CLASS_NAME,
				`${this._baseUrl}/api/remove-policy?id=${this._encodedEnforcerId}`,
				HttpMethod.POST,
				{
					ptype: "g",
					v0: this.applyTenant(tenantId, subject),
					v1: this.applyTenant(tenantId, role)
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
	 * @param subject The subject to remove all roles from.
	 * @returns Nothing.
	 * @throws GeneralError if the request fails.
	 */
	public async removeAllRolesForSubject(subject: string): Promise<void> {
		Guards.stringValue(CasbinAuthorizationConnector.CLASS_NAME, nameof(subject), subject);

		try {
			const tenantId = await this.getTenantId();
			const prefixedSubject = this.applyTenant(tenantId, subject);
			const rules = await this.getAllRawPolicies();
			const subjectRoles = rules.filter(r => r.Ptype === "g" && r.V0 === prefixedSubject);
			for (const rule of subjectRoles) {
				await this.removeRoleForSubject(subject, this.stripTenant(tenantId, rule.V1));
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
	 * @param subject The subject to query.
	 * @returns The assigned roles.
	 * @throws GeneralError if the query fails.
	 */
	public async getRolesForSubject(subject: string): Promise<string[]> {
		Guards.stringValue(CasbinAuthorizationConnector.CLASS_NAME, nameof(subject), subject);

		try {
			const tenantId = await this.getTenantId();
			const prefixedSubject = this.applyTenant(tenantId, subject);
			const rules = await this.getAllRawPolicies();
			return rules
				.filter(r => r.Ptype === "g" && r.V0 === prefixedSubject)
				.map(r => this.stripTenant(tenantId, r.V1));
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
	 * @param role The role to query.
	 * @returns The subjects with the given role.
	 * @throws GeneralError if the query fails.
	 */
	public async getSubjectsForRole(role: string): Promise<string[]> {
		Guards.stringValue(CasbinAuthorizationConnector.CLASS_NAME, nameof(role), role);

		try {
			const tenantId = await this.getTenantId();
			const prefixedRole = this.applyTenant(tenantId, role);
			const rules = await this.getAllRawPolicies();
			return rules
				.filter(r => r.Ptype === "g" && r.V1 === prefixedRole && this.isTenantValue(tenantId, r.V0))
				.map(r => this.stripTenant(tenantId, r.V0));
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
	 * @param subject The subject to check.
	 * @param role The role to check for.
	 * @returns True if the subject has the role.
	 * @throws GeneralError if the request fails.
	 */
	public async hasRoleForSubject(subject: string, role: string): Promise<boolean> {
		Guards.stringValue(CasbinAuthorizationConnector.CLASS_NAME, nameof(subject), subject);
		Guards.stringValue(CasbinAuthorizationConnector.CLASS_NAME, nameof(role), role);

		try {
			const tenantId = await this.getTenantId();
			const rules = await this.getAllRawPolicies();
			return rules.some(
				r =>
					r.Ptype === "g" &&
					r.V0 === this.applyTenant(tenantId, subject) &&
					r.V1 === this.applyTenant(tenantId, role)
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
	 * @param role The child role that will inherit permissions from the parent.
	 * @param parentRole The parent role whose permissions are inherited.
	 * @returns Nothing.
	 * @throws GeneralError if the request fails.
	 */
	public async addRoleInheritance(role: string, parentRole: string): Promise<void> {
		Guards.stringValue(CasbinAuthorizationConnector.CLASS_NAME, nameof(role), role);
		Guards.stringValue(CasbinAuthorizationConnector.CLASS_NAME, nameof(parentRole), parentRole);

		try {
			const tenantId = await this.getTenantId();
			const response = await FetchHelper.fetchJson<
				{ ptype: string; v0: string; v1: string },
				ICasbinServerResponse<string>
			>(
				CasbinAuthorizationConnector.CLASS_NAME,
				`${this._baseUrl}/api/add-policy?id=${this._encodedEnforcerId}`,
				HttpMethod.POST,
				{
					ptype: "g",
					v0: this.applyTenant(tenantId, role),
					v1: this.applyTenant(tenantId, parentRole)
				},
				this._requestOptions
			);

			this.assertOk(response, "addRoleInheritanceFailed", { role, parentRole });
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				CasbinAuthorizationConnector.CLASS_NAME,
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
		Guards.stringValue(CasbinAuthorizationConnector.CLASS_NAME, nameof(role), role);
		Guards.stringValue(CasbinAuthorizationConnector.CLASS_NAME, nameof(parentRole), parentRole);

		try {
			const tenantId = await this.getTenantId();
			const response = await FetchHelper.fetchJson<
				{ ptype: string; v0: string; v1: string },
				ICasbinServerResponse<string>
			>(
				CasbinAuthorizationConnector.CLASS_NAME,
				`${this._baseUrl}/api/remove-policy?id=${this._encodedEnforcerId}`,
				HttpMethod.POST,
				{
					ptype: "g",
					v0: this.applyTenant(tenantId, role),
					v1: this.applyTenant(tenantId, parentRole)
				},
				this._requestOptions
			);

			this.assertOk(response, "removeRoleInheritanceFailed", { role, parentRole });
		} catch (err) {
			if (BaseError.isErrorName(err, GeneralError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				CasbinAuthorizationConnector.CLASS_NAME,
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
		Guards.stringValue(CasbinAuthorizationConnector.CLASS_NAME, nameof(role), role);

		try {
			const tenantId = await this.getTenantId();
			const prefixedRole = this.applyTenant(tenantId, role);
			const rules = await this.getAllRawPolicies();
			return rules
				.filter(r => r.Ptype === "g" && r.V0 === prefixedRole && this.isTenantValue(tenantId, r.V1))
				.map(r => this.stripTenant(tenantId, r.V1));
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
	 * @param role The role to query.
	 * @returns The child roles.
	 * @throws GeneralError if the query fails.
	 */
	public async getChildRoles(role: string): Promise<string[]> {
		Guards.stringValue(CasbinAuthorizationConnector.CLASS_NAME, nameof(role), role);

		try {
			const tenantId = await this.getTenantId();
			const prefixedRole = this.applyTenant(tenantId, role);
			const rules = await this.getAllRawPolicies();
			return rules
				.filter(r => r.Ptype === "g" && r.V1 === prefixedRole && this.isTenantValue(tenantId, r.V0))
				.map(r => this.stripTenant(tenantId, r.V0));
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
	 * Get the tenant ID from the ambient context store.
	 * @returns The tenant ID string, or undefined when no tenant context is active.
	 * @internal
	 */
	private async getTenantId(): Promise<string | undefined> {
		const contextIds = await ContextIdStore.getContextIds();
		const tenantId = contextIds?.[ContextIdKeys.Tenant];
		return Is.stringValue(tenantId) ? tenantId : undefined;
	}

	/**
	 * Prefix a value with the tenant ID when a tenant is active.
	 * @param tenantId The active tenant ID, or undefined.
	 * @param value The value to prefix.
	 * @returns The prefixed value, or the original value when no tenant is active.
	 * @internal
	 */
	private applyTenant(tenantId: string | undefined, value: string): string {
		return tenantId !== undefined ? `${tenantId}:${value}` : value;
	}

	/**
	 * Strip the tenant prefix from a value when a tenant is active.
	 * @param tenantId The active tenant ID, or undefined.
	 * @param value The value to strip.
	 * @returns The value with the tenant prefix removed, or the original value when no tenant is active.
	 * @internal
	 */
	private stripTenant(tenantId: string | undefined, value: string): string {
		if (tenantId === undefined) {
			return value;
		}
		const prefix = `${tenantId}:`;
		return value.startsWith(prefix) ? value.slice(prefix.length) : value;
	}

	/**
	 * Return true when a value belongs to the current tenant (or no tenant is active).
	 * @param tenantId The active tenant ID, or undefined.
	 * @param value The value to test.
	 * @returns True if the value belongs to the current tenant.
	 * @internal
	 */
	private isTenantValue(tenantId: string | undefined, value: string): boolean {
		return tenantId === undefined || value.startsWith(`${tenantId}:`);
	}

	/**
	 * Fetch all raw policy rules from the Casdoor enforcer.
	 * @returns All rules (both "p" permission and "g" grouping types).
	 * @throws GeneralError if the fetch fails.
	 * @internal
	 */
	private async getAllRawPolicies(): Promise<ICasdoorPolicyRule[]> {
		const response = await FetchHelper.fetchJson<
			never,
			ICasbinServerResponse<ICasdoorPolicyRule[]>
		>(
			CasbinAuthorizationConnector.CLASS_NAME,
			`${this._baseUrl}/api/get-policies?id=${this._encodedEnforcerId}`,
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
}
