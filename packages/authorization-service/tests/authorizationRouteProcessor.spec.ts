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
	type IAuthorizationModel
} from "@twin.org/authorization-models";
import { ContextIdKeys, ContextIdStore, type IContextIds } from "@twin.org/context";
import { ComponentFactory } from "@twin.org/core";
import { MemoryEntityStorageConnector } from "@twin.org/entity-storage-connector-memory";
import { EntityStorageConnectorFactory } from "@twin.org/entity-storage-models";
import { nameof } from "@twin.org/nameof";
import { HttpStatusCode } from "@twin.org/web";
import { authorizationAddRoleForSubject } from "../src/authorizationRoutes.js";
import { AuthorizationService } from "../src/authorizationService.js";
import { AuthorizationRouteProcessor } from "../src/processors/authorizationRouteProcessor.js";

const TEST_NAMESPACE = "test-es";
const COMPONENT_TYPE = "authorization";
const TEST_MODEL_ID = "system";

describe("AuthorizationRouteProcessor (entity-storage backed)", () => {
	let policyStorage: MemoryEntityStorageConnector<AuthorizationPolicy>;
	let roleStorage: MemoryEntityStorageConnector<AuthorizationRoleAssignment>;
	let inheritanceStorage: MemoryEntityStorageConnector<AuthorizationRoleInheritance>;
	let roleNameStorage: MemoryEntityStorageConnector<AuthorizationRoleName>;
	let service: AuthorizationService;
	let processor: AuthorizationRouteProcessor;

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

		processor = new AuthorizationRouteProcessor({
			config: { authorizationModelId: TEST_MODEL_ID }
		});
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
		return { headers: {}, body: {} };
	}

	function makeRoute(
		operationId: string,
		requiresAuthorization: boolean | undefined = true,
		skipAuth?: boolean
	): IBaseRoute {
		return { operationId, path: "/api/test", requiresAuthorization, skipAuth };
	}

	function makeContextIds(userId?: string): IContextIds {
		return userId !== undefined ? { [ContextIdKeys.User]: userId } : {};
	}

	async function initialize(rules: IAuthorizationModel): Promise<void> {
		for (const policy of rules.policies ?? []) {
			await service.addPolicy(TEST_MODEL_ID, policy.subject, policy.object, policy.action);
		}
		for (const inheritance of rules.roleInheritances ?? []) {
			await service.addRoleInheritance(TEST_MODEL_ID, inheritance.role, inheritance.inheritsFrom);
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

			expect(response.statusCode).toBeUndefined();
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
				policies: [{ subject: "editor", object: "reportRead", action: "execute" }]
			});
			await service.addRoleForSubject(TEST_MODEL_ID, "user-alice", "editor");

			const response = makeResponse();
			await processor.pre(
				makeRequest(),
				response,
				makeRoute("reportRead"),
				makeContextIds("user-alice"),
				{}
			);

			expect(response.statusCode).toBeUndefined();
		});

		test("denies when the userId's assigned role has no policy for the operationId", async () => {
			await initialize({
				policies: [{ subject: "admin", object: "reportDelete", action: "execute" }]
			});
			await service.addRoleForSubject(TEST_MODEL_ID, "user-alice", "editor");

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
				policies: [{ subject: "admin", object: "settingsWrite", action: "execute" }]
			});
			await service.addRoleForSubject(TEST_MODEL_ID, "user-bob", "viewer");
			await service.addRoleForSubject(TEST_MODEL_ID, "user-bob", "admin");

			const response = makeResponse();
			await processor.pre(
				makeRequest(),
				response,
				makeRoute("settingsWrite"),
				makeContextIds("user-bob"),
				{}
			);

			expect(response.statusCode).toBeUndefined();
		});

		test("denies when all of the userId's assigned roles lack a policy for the operationId", async () => {
			await initialize({
				policies: [{ subject: "admin", object: "settingsWrite", action: "execute" }]
			});
			await service.addRoleForSubject(TEST_MODEL_ID, "user-bob", "viewer");
			await service.addRoleForSubject(TEST_MODEL_ID, "user-bob", "editor");

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

		test("applies multiple policies and role assignments", async () => {
			await initialize({
				policies: [
					{ subject: "viewer", object: "reportRead", action: "execute" },
					{ subject: "editor", object: "reportWrite", action: "execute" }
				]
			});
			await service.addRoleForSubject(TEST_MODEL_ID, "user-carol", "viewer");
			await service.addRoleForSubject(TEST_MODEL_ID, "user-carol", "editor");

			const readResponse = makeResponse();
			await processor.pre(
				makeRequest(),
				readResponse,
				makeRoute("reportRead"),
				makeContextIds("user-carol"),
				{}
			);
			expect(readResponse.statusCode).toBeUndefined();

			const writeResponse = makeResponse();
			await processor.pre(
				makeRequest(),
				writeResponse,
				makeRoute("reportWrite"),
				makeContextIds("user-carol"),
				{}
			);
			expect(writeResponse.statusCode).toBeUndefined();
		});
	});

	describe("role inheritance", () => {
		test("allows when the userId's role inherits from a parent role that has the policy", async () => {
			// user-alice → "admin", admin inherits "superAdmin", superAdmin holds the policy.
			await initialize({
				policies: [{ subject: "superAdmin", object: "tenantDelete", action: "execute" }],
				roleInheritances: [{ role: "admin", inheritsFrom: "superAdmin" }]
			});
			await service.addRoleForSubject(TEST_MODEL_ID, "user-alice", "admin");

			const response = makeResponse();
			await processor.pre(
				makeRequest(),
				response,
				makeRoute("tenantDelete"),
				makeContextIds("user-alice"),
				{}
			);

			expect(response.statusCode).toBeUndefined();
		});

		test("allows via a deep roleInheritance chain from the userId's assigned role", async () => {
			// user-dave → "operator", operator inherits "manager", manager inherits "root", root holds the policy.
			await initialize({
				policies: [{ subject: "root", object: "systemReset", action: "execute" }],
				roleInheritances: [
					{ role: "operator", inheritsFrom: "manager" },
					{ role: "manager", inheritsFrom: "root" }
				]
			});
			await service.addRoleForSubject(TEST_MODEL_ID, "user-dave", "operator");

			const response = makeResponse();
			await processor.pre(
				makeRequest(),
				response,
				makeRoute("systemReset"),
				makeContextIds("user-dave"),
				{}
			);

			expect(response.statusCode).toBeUndefined();
		});

		test("denies when no chain from the userId leads to a matching policy", async () => {
			await initialize({
				policies: [{ subject: "superAdmin", object: "tenantDelete", action: "execute" }]
			});
			await service.addRoleForSubject(TEST_MODEL_ID, "user-alice", "editor");

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
				roleInheritances: [{ role: "admin", inheritsFrom: "superAdmin" }]
			});
			await service.addRoleForSubject(TEST_MODEL_ID, "user-eve", "viewer");
			await service.addRoleForSubject(TEST_MODEL_ID, "user-eve", "admin");

			const response = makeResponse();
			await processor.pre(
				makeRequest(),
				response,
				makeRoute("auditPurge"),
				makeContextIds("user-eve"),
				{}
			);

			expect(response.statusCode).toBeUndefined();
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

			expect(response.statusCode).toBeUndefined();
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

			expect(response.statusCode).toBeUndefined();
		});

		test("denies when no userId is present in context", async () => {
			await initialize({});

			const response = makeResponse();
			await processor.pre(makeRequest(), response, makeRoute("secureAction"), makeContextIds(), {});

			expect(response.statusCode).toBe(HttpStatusCode.unauthorized);
		});

		test("bypasses the check when skipAuth is true even with no userId in context", async () => {
			await initialize({});

			const response = makeResponse();
			await processor.pre(
				makeRequest(),
				response,
				makeRoute("systemAction", undefined, true),
				makeContextIds(),
				{}
			);

			expect(response.statusCode).toBeUndefined();
		});

		test("does not overwrite a response already set by an earlier processor", async () => {
			await initialize({});

			const response = makeResponse();
			const originalBody = { name: "invalidToken", message: "The token was invalid." };
			response.statusCode = HttpStatusCode.unauthorized;
			response.body = originalBody;

			await processor.pre(makeRequest(), response, makeRoute("secureAction"), makeContextIds(), {});

			expect(response.statusCode).toBe(HttpStatusCode.unauthorized);
			expect(response.body).toBe(originalBody);
		});
	});

	describe("addRoleForSubject privilege escalation guard", () => {
		const HTTP_CTX = { serverRequest: { url: "/", headers: {} }, processorState: {} };
		const MODEL_ID = TEST_MODEL_ID;

		test("allows caller to grant a role they directly hold", async () => {
			await service.addRoleForSubject(MODEL_ID, "user-admin", "editor");

			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await expect(
					authorizationAddRoleForSubject(HTTP_CTX, COMPONENT_TYPE, {
						pathParams: { modelId: MODEL_ID, subject: "user-bob" },
						body: { role: "editor" }
					})
				).resolves.toMatchObject({ statusCode: HttpStatusCode.noContent });
			});
		});

		test("denies caller granting a descendant role they do not directly hold", async () => {
			await service.addRoleInheritance(MODEL_ID, "super-admin", "tenant-admin");
			await service.addRoleForSubject(MODEL_ID, "user-admin", "tenant-admin");

			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await expect(
					authorizationAddRoleForSubject(HTTP_CTX, COMPONENT_TYPE, {
						pathParams: { modelId: MODEL_ID, subject: "user-bob" },
						body: { role: "super-admin" }
					})
				).rejects.toThrow();
			});
		});

		test("allows caller to grant a role they do not directly hold", async () => {
			await service.addRoleForSubject(MODEL_ID, "user-admin", "editor");

			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await expect(
					authorizationAddRoleForSubject(HTTP_CTX, COMPONENT_TYPE, {
						pathParams: { modelId: MODEL_ID, subject: "user-bob" },
						body: { role: "devops" }
					})
				).resolves.toMatchObject({ statusCode: HttpStatusCode.noContent });
			});
		});

		test("denies caller granting a descendant role of their role", async () => {
			await service.addRoleInheritance(MODEL_ID, "super-editor", "editor");
			await service.addRoleForSubject(MODEL_ID, "user-admin", "editor");

			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await expect(
					authorizationAddRoleForSubject(HTTP_CTX, COMPONENT_TYPE, {
						pathParams: { modelId: MODEL_ID, subject: "user-bob" },
						body: { role: "super-editor" }
					})
				).rejects.toThrow();
			});
		});

		test("allows granting when no userId is in context (system call)", async () => {
			await ContextIdStore.run({}, async () => {
				await expect(
					authorizationAddRoleForSubject(HTTP_CTX, COMPONENT_TYPE, {
						pathParams: { modelId: MODEL_ID, subject: "user-bob" },
						body: { role: "editor" }
					})
				).resolves.toMatchObject({ statusCode: HttpStatusCode.noContent });
			});
		});
	});
});
