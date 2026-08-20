// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IBaseRoute, IHttpResponse, IHttpServerRequest } from "@twin.org/api-models";
import {
	type AuthorizationPolicy,
	type AuthorizationRoleAssignment,
	type AuthorizationRoleInheritance,
	type AuthorizationRoleName,
	EntityStorageAuthorizationConnector,
	initSchema
} from "@twin.org/authorization-connector-entity-storage";
import {
	AuthorizationConnectorFactory,
	type IAuthorizationRules
} from "@twin.org/authorization-models";
import { ContextIdKeys, type IContextIds } from "@twin.org/context";
import { ComponentFactory } from "@twin.org/core";
import { MemoryEntityStorageConnector } from "@twin.org/entity-storage-connector-memory";
import { EntityStorageConnectorFactory } from "@twin.org/entity-storage-models";
import { nameof } from "@twin.org/nameof";
import { HttpStatusCode } from "@twin.org/web";
import { AuthorizationService } from "../src/authorizationService.js";
import { AuthorizationProcessor } from "../src/processors/authorizationProcessor.js";

const TEST_NAMESPACE = "test-es";
const COMPONENT_TYPE = "authorization";

describe("AuthorizationProcessor (entity-storage backed)", () => {
	let policyStorage: MemoryEntityStorageConnector<AuthorizationPolicy>;
	let roleStorage: MemoryEntityStorageConnector<AuthorizationRoleAssignment>;
	let inheritanceStorage: MemoryEntityStorageConnector<AuthorizationRoleInheritance>;
	let roleNameStorage: MemoryEntityStorageConnector<AuthorizationRoleName>;
	let service: AuthorizationService;
	let processor: AuthorizationProcessor;

	beforeEach(async () => {
		initSchema();

		policyStorage = new MemoryEntityStorageConnector<AuthorizationPolicy>({
			entitySchema: nameof<AuthorizationPolicy>(),
			config: { storageKey: "authorization-policy" }
		});
		await policyStorage.teardown();
		EntityStorageConnectorFactory.register("authorization-policy", () => policyStorage);

		roleStorage = new MemoryEntityStorageConnector<AuthorizationRoleAssignment>({
			entitySchema: nameof<AuthorizationRoleAssignment>(),
			config: { storageKey: "authorization-role-assignment" }
		});
		await roleStorage.teardown();
		EntityStorageConnectorFactory.register("authorization-role-assignment", () => roleStorage);

		inheritanceStorage = new MemoryEntityStorageConnector<AuthorizationRoleInheritance>({
			entitySchema: nameof<AuthorizationRoleInheritance>(),
			config: { storageKey: "authorization-role-inheritance" }
		});
		await inheritanceStorage.teardown();
		EntityStorageConnectorFactory.register(
			"authorization-role-inheritance",
			() => inheritanceStorage
		);

		roleNameStorage = new MemoryEntityStorageConnector<AuthorizationRoleName>({
			entitySchema: nameof<AuthorizationRoleName>(),
			config: { storageKey: "authorization-role-name" }
		});
		await roleNameStorage.teardown();
		EntityStorageConnectorFactory.register("authorization-role-name", () => roleNameStorage);

		AuthorizationConnectorFactory.register(
			TEST_NAMESPACE,
			() => new EntityStorageAuthorizationConnector()
		);

		service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
		ComponentFactory.register(COMPONENT_TYPE, () => service);

		processor = new AuthorizationProcessor();
	});

	afterEach(async () => {
		ComponentFactory.unregister(COMPONENT_TYPE);
		AuthorizationConnectorFactory.unregister(TEST_NAMESPACE);
		EntityStorageConnectorFactory.unregister("authorization-policy");
		EntityStorageConnectorFactory.unregister("authorization-role-assignment");
		EntityStorageConnectorFactory.unregister("authorization-role-inheritance");
		EntityStorageConnectorFactory.unregister("authorization-role-name");
		await policyStorage.teardown();
		await roleStorage.teardown();
		await inheritanceStorage.teardown();
		await roleNameStorage.teardown();
	});

	function makeRequest(): IHttpServerRequest {
		return { url: "/api/test", headers: {} };
	}

	function makeResponse(): IHttpResponse {
		return { statusCode: HttpStatusCode.ok, headers: {}, body: {} };
	}

	function makeRoute(operationId: string, requiresAuthorization?: boolean): IBaseRoute {
		return { operationId, path: "/api/test", requiresAuthorization };
	}

	function makeContextIds(userId?: string): IContextIds {
		return userId !== undefined ? { [ContextIdKeys.User]: userId } : {};
	}

	async function initialize(rules: IAuthorizationRules): Promise<void> {
		for (const policy of rules.policies ?? []) {
			await service.addPolicy(policy);
		}
		for (const assignment of rules.roleAssignments ?? []) {
			await service.addRoleForSubject(assignment.subject, assignment.role);
		}
		for (const inheritance of rules.roleInheritances ?? []) {
			await service.addRoleInheritance(inheritance.role, inheritance.parentRole);
		}
	}

	describe("direct userId policy", () => {
		test("allows when the userId has a direct execute policy for the operationId", async () => {
			await initialize({
				policies: [{ subject: "user-alice", object: "documentUpdate", action: "execute" }]
			});

			const response = makeResponse();
			await processor.pre(
				makeRequest(),
				response,
				makeRoute("documentUpdate"),
				makeContextIds("user-alice"),
				{}
			);

			expect(response.statusCode).toBe(HttpStatusCode.ok);
		});

		test("denies when the userId has no execute policy for the operationId", async () => {
			await initialize({
				policies: [{ subject: "user-alice", object: "documentUpdate", action: "execute" }]
			});

			const response = makeResponse();
			await processor.pre(
				makeRequest(),
				response,
				makeRoute("documentUpdate"),
				makeContextIds("user-bob"),
				{}
			);

			expect(response.statusCode).toBe(HttpStatusCode.unauthorized);
		});
	});

	describe("userId via role assignment", () => {
		test("allows when the userId is assigned a role with a matching policy", async () => {
			await initialize({
				policies: [{ subject: "editor", object: "reportRead", action: "execute" }],
				roleAssignments: [{ subject: "user-alice", role: "editor" }]
			});

			const response = makeResponse();
			await processor.pre(
				makeRequest(),
				response,
				makeRoute("reportRead"),
				makeContextIds("user-alice"),
				{}
			);

			expect(response.statusCode).toBe(HttpStatusCode.ok);
		});

		test("denies when the userId's assigned role has no policy for the operationId", async () => {
			await initialize({
				policies: [{ subject: "admin", object: "reportDelete", action: "execute" }],
				roleAssignments: [{ subject: "user-alice", role: "editor" }]
			});

			const response = makeResponse();
			await processor.pre(
				makeRequest(),
				response,
				makeRoute("reportDelete"),
				makeContextIds("user-alice"),
				{}
			);

			expect(response.statusCode).toBe(HttpStatusCode.unauthorized);
		});

		test("allows when one of the userId's multiple assigned roles has a matching policy", async () => {
			await initialize({
				policies: [{ subject: "admin", object: "settingsWrite", action: "execute" }],
				roleAssignments: [
					{ subject: "user-bob", role: "viewer" },
					{ subject: "user-bob", role: "admin" }
				]
			});

			const response = makeResponse();
			await processor.pre(
				makeRequest(),
				response,
				makeRoute("settingsWrite"),
				makeContextIds("user-bob"),
				{}
			);

			expect(response.statusCode).toBe(HttpStatusCode.ok);
		});

		test("denies when all of the userId's assigned roles lack a policy for the operationId", async () => {
			await initialize({
				policies: [{ subject: "admin", object: "settingsWrite", action: "execute" }],
				roleAssignments: [
					{ subject: "user-bob", role: "viewer" },
					{ subject: "user-bob", role: "editor" }
				]
			});

			const response = makeResponse();
			await processor.pre(
				makeRequest(),
				response,
				makeRoute("settingsWrite"),
				makeContextIds("user-bob"),
				{}
			);

			expect(response.statusCode).toBe(HttpStatusCode.unauthorized);
		});

		test("applies multiple policies and role assignments in a single initialize call", async () => {
			await initialize({
				policies: [
					{ subject: "viewer", object: "reportRead", action: "execute" },
					{ subject: "editor", object: "reportWrite", action: "execute" }
				],
				roleAssignments: [
					{ subject: "user-carol", role: "viewer" },
					{ subject: "user-carol", role: "editor" }
				]
			});

			const readResponse = makeResponse();
			await processor.pre(
				makeRequest(),
				readResponse,
				makeRoute("reportRead"),
				makeContextIds("user-carol"),
				{}
			);
			expect(readResponse.statusCode).toBe(HttpStatusCode.ok);

			const writeResponse = makeResponse();
			await processor.pre(
				makeRequest(),
				writeResponse,
				makeRoute("reportWrite"),
				makeContextIds("user-carol"),
				{}
			);
			expect(writeResponse.statusCode).toBe(HttpStatusCode.ok);
		});
	});

	describe("role inheritance", () => {
		test("allows when the userId's role inherits from a parent role that has the policy", async () => {
			// user-alice → "admin" (roleAssignment), admin inherits "superAdmin" (roleInheritance),
			// superAdmin holds the policy.
			await initialize({
				policies: [{ subject: "superAdmin", object: "tenantDelete", action: "execute" }],
				roleAssignments: [{ subject: "user-alice", role: "admin" }],
				roleInheritances: [{ role: "admin", parentRole: "superAdmin" }]
			});

			const response = makeResponse();
			await processor.pre(
				makeRequest(),
				response,
				makeRoute("tenantDelete"),
				makeContextIds("user-alice"),
				{}
			);

			expect(response.statusCode).toBe(HttpStatusCode.ok);
		});

		test("allows via a deep roleInheritance chain from the userId's assigned role", async () => {
			// user-dave → "operator" (roleAssignment), operator inherits "manager" (roleInheritance),
			// manager inherits "root" (roleInheritance), root holds the policy.
			await initialize({
				policies: [{ subject: "root", object: "systemReset", action: "execute" }],
				roleAssignments: [{ subject: "user-dave", role: "operator" }],
				roleInheritances: [
					{ role: "operator", parentRole: "manager" },
					{ role: "manager", parentRole: "root" }
				]
			});

			const response = makeResponse();
			await processor.pre(
				makeRequest(),
				response,
				makeRoute("systemReset"),
				makeContextIds("user-dave"),
				{}
			);

			expect(response.statusCode).toBe(HttpStatusCode.ok);
		});

		test("denies when no chain from the userId leads to a matching policy", async () => {
			await initialize({
				policies: [{ subject: "superAdmin", object: "tenantDelete", action: "execute" }],
				roleAssignments: [{ subject: "user-alice", role: "editor" }]
			});

			const response = makeResponse();
			await processor.pre(
				makeRequest(),
				response,
				makeRoute("tenantDelete"),
				makeContextIds("user-alice"),
				{}
			);

			expect(response.statusCode).toBe(HttpStatusCode.unauthorized);
		});

		test("allows when one of the userId's role chains satisfies while another does not", async () => {
			// user-eve has two roles: "viewer" (no chain to policy) and "admin" (inherits superAdmin).
			await initialize({
				policies: [{ subject: "superAdmin", object: "auditPurge", action: "execute" }],
				roleAssignments: [
					{ subject: "user-eve", role: "viewer" },
					{ subject: "user-eve", role: "admin" }
				],
				roleInheritances: [{ role: "admin", parentRole: "superAdmin" }]
			});

			const response = makeResponse();
			await processor.pre(
				makeRequest(),
				response,
				makeRoute("auditPurge"),
				makeContextIds("user-eve"),
				{}
			);

			expect(response.statusCode).toBe(HttpStatusCode.ok);
		});
	});

	describe("route authorization flags", () => {
		test("bypasses the check when requiresAuthorization is false", async () => {
			const response = makeResponse();
			await processor.pre(
				makeRequest(),
				response,
				makeRoute("publicRead", false),
				makeContextIds(),
				{}
			);

			expect(response.statusCode).toBe(HttpStatusCode.ok);
		});

		test("applies the check and denies when requiresAuthorization is true and no policy matches", async () => {
			await initialize({});

			const response = makeResponse();
			await processor.pre(
				makeRequest(),
				response,
				makeRoute("protectedAction"),
				makeContextIds("user-unknown"),
				{}
			);

			expect(response.statusCode).toBe(HttpStatusCode.unauthorized);
		});

		test("skips the check entirely when no route is matched", async () => {
			const response = makeResponse();
			await processor.pre(makeRequest(), response, undefined, makeContextIds(), {});

			expect(response.statusCode).toBe(HttpStatusCode.ok);
		});

		test("denies when contextIds has no userId and no defaultRole is configured", async () => {
			await initialize({});

			const response = makeResponse();
			await processor.pre(makeRequest(), response, makeRoute("secureAction"), makeContextIds(), {});

			expect(response.statusCode).toBe(HttpStatusCode.unauthorized);
		});
	});

	describe("defaultRole fallback", () => {
		test("uses the configured defaultRole when contextIds carries no userId", async () => {
			await initialize({
				policies: [{ subject: "guest", object: "homeView", action: "execute" }]
			});

			processor = new AuthorizationProcessor({ config: { defaultRole: "guest" } });

			const response = makeResponse();
			await processor.pre(makeRequest(), response, makeRoute("homeView"), makeContextIds(), {});

			expect(response.statusCode).toBe(HttpStatusCode.ok);
		});

		test("denies when contextIds carries no userId and the defaultRole has no matching policy", async () => {
			await initialize({
				policies: [{ subject: "admin", object: "adminPanel", action: "execute" }]
			});

			processor = new AuthorizationProcessor({ config: { defaultRole: "guest" } });

			const response = makeResponse();
			await processor.pre(makeRequest(), response, makeRoute("adminPanel"), makeContextIds(), {});

			expect(response.statusCode).toBe(HttpStatusCode.unauthorized);
		});

		test("prefers the userId over the defaultRole when userId is present", async () => {
			await initialize({
				policies: [{ subject: "editor", object: "docWrite", action: "execute" }],
				roleAssignments: [{ subject: "user-alice", role: "editor" }]
			});

			processor = new AuthorizationProcessor({ config: { defaultRole: "guest" } });

			const response = makeResponse();
			await processor.pre(
				makeRequest(),
				response,
				makeRoute("docWrite"),
				makeContextIds("user-alice"),
				{}
			);

			expect(response.statusCode).toBe(HttpStatusCode.ok);
		});
	});
});
