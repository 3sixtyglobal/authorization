// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import {
	type AuthorizationPolicy,
	type AuthorizationRoleAssignment,
	type AuthorizationRoleInheritance,
	type AuthorizationRoleName,
	EntityStorageAuthorizationConnector,
	initSchema
} from "@twin.org/authorization-connector-entity-storage";
import { AuthorizationConnectorFactory } from "@twin.org/authorization-models";
import { ContextIdKeys, ContextIdStore } from "@twin.org/context";
import { SharedStore } from "@twin.org/core";
import { MemoryEntityStorageConnector } from "@twin.org/entity-storage-connector-memory";
import { EntityStorageConnectorFactory } from "@twin.org/entity-storage-models";
import { nameof } from "@twin.org/nameof";
import { AuthorizationService } from "../src/authorizationService.js";

const TEST_NAMESPACE = "test";
const TEST_MODEL_ID = "test-model-id";

describe("AuthorizationService", () => {
	let connector: EntityStorageAuthorizationConnector;
	let policyStorage: MemoryEntityStorageConnector<AuthorizationPolicy>;
	let roleStorage: MemoryEntityStorageConnector<AuthorizationRoleAssignment>;
	let inheritanceStorage: MemoryEntityStorageConnector<AuthorizationRoleInheritance>;
	let roleNameStorage: MemoryEntityStorageConnector<AuthorizationRoleName>;

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

		connector = new EntityStorageAuthorizationConnector();
		AuthorizationConnectorFactory.register(TEST_NAMESPACE, () => connector);
	});

	afterEach(async () => {
		vi.restoreAllMocks();
		SharedStore.remove("migrationUserRoles");
		AuthorizationConnectorFactory.unregister(TEST_NAMESPACE);
		await policyStorage.teardown();
		await roleStorage.teardown();
		await inheritanceStorage.teardown();
		await roleNameStorage.teardown();
	});

	test("Can create an instance", async () => {
		const service = new AuthorizationService();
		expect(service).toBeDefined();
	});

	describe("check cache", () => {
		test("returns cached result without calling connector again", async () => {
			await connector.addPolicy(TEST_MODEL_ID, "alice", "/data", "read");
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			const r1 = await service.check(TEST_MODEL_ID, "alice", "/data", "read");
			const r2 = await service.check(TEST_MODEL_ID, "alice", "/data", "read");

			expect(r1).toBe(true);
			expect(r2).toBe(true);
			expect(spy).toHaveBeenCalledTimes(1);
		});

		test.each([
			[
				"addPolicy",
				"alice",
				async (svc: AuthorizationService) => svc.addPolicy(TEST_MODEL_ID, "alice", "/data", "read")
			],
			[
				"removePolicy",
				"alice",
				async (svc: AuthorizationService) =>
					svc.removePolicy(TEST_MODEL_ID, "alice", "/data", "read")
			],
			[
				"addRoleForSubject",
				"alice",
				async (svc: AuthorizationService) => svc.addRoleForSubject(TEST_MODEL_ID, "alice", "admin")
			],
			[
				"removeRoleForSubject",
				"alice",
				async (svc: AuthorizationService) =>
					svc.removeRoleForSubject(TEST_MODEL_ID, "alice", "admin")
			],
			[
				"removeAllRolesForSubject",
				"alice",
				async (svc: AuthorizationService) => svc.removeAllRolesForSubject(TEST_MODEL_ID, "alice")
			],
			[
				"addRoleInheritance",
				"editor",
				async (svc: AuthorizationService) =>
					svc.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer")
			],
			[
				"removeRoleInheritance",
				"editor",
				async (svc: AuthorizationService) =>
					svc.removeRoleInheritance(TEST_MODEL_ID, "editor", "viewer")
			]
		])("invalidates cache after %s", async (label, subject, mutate) => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await service.check(TEST_MODEL_ID, subject, "/data", "read");
			await mutate(service);
			await service.check(TEST_MODEL_ID, subject, "/data", "read");

			expect(spy).toHaveBeenCalledTimes(2);
		});

		test("cache keys are tenant-aware", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantA" }, async () =>
				service.check(TEST_MODEL_ID, "alice", "/data", "read")
			);
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantB" }, async () =>
				service.check(TEST_MODEL_ID, "alice", "/data", "read")
			);

			expect(spy).toHaveBeenCalledTimes(2);
		});

		test("invalidation only affects the current tenant", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantA" }, async () =>
				service.check(TEST_MODEL_ID, "alice", "/data", "read")
			);
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantB" }, async () =>
				service.check(TEST_MODEL_ID, "alice", "/data", "read")
			);
			expect(spy).toHaveBeenCalledTimes(2);

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantA" }, async () =>
				service.addPolicy(TEST_MODEL_ID, "alice", "/data", "read")
			);

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantA" }, async () =>
				service.check(TEST_MODEL_ID, "alice", "/data", "read")
			);
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantB" }, async () =>
				service.check(TEST_MODEL_ID, "alice", "/data", "read")
			);

			expect(spy).toHaveBeenCalledTimes(3);
		});

		test("caches false results", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			const r1 = await service.check(TEST_MODEL_ID, "alice", "/data", "read");
			const r2 = await service.check(TEST_MODEL_ID, "alice", "/data", "read");

			expect(r1).toBe(false);
			expect(r2).toBe(false);
			expect(spy).toHaveBeenCalledTimes(1);
		});

		test("addPolicy only invalidates the exact matching key", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // call 1
			await service.check(TEST_MODEL_ID, "alice", "/data", "write"); // call 2

			await service.addPolicy(TEST_MODEL_ID, "alice", "/data", "read");

			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // invalidated — call 3
			await service.check(TEST_MODEL_ID, "alice", "/data", "write"); // still cached

			expect(spy).toHaveBeenCalledTimes(3);
		});

		test("removePolicy only invalidates the exact matching key", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // call 1
			await service.check(TEST_MODEL_ID, "alice", "/data", "write"); // call 2

			await service.removePolicy(TEST_MODEL_ID, "alice", "/data", "read");

			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // invalidated — call 3
			await service.check(TEST_MODEL_ID, "alice", "/data", "write"); // still cached

			expect(spy).toHaveBeenCalledTimes(3);
		});

		test("addRoleForSubject invalidates all keys for the subject but not other subjects", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // call 1
			await service.check(TEST_MODEL_ID, "alice", "/files", "write"); // call 2
			await service.check(TEST_MODEL_ID, "bob", "/data", "read"); // call 3

			await service.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");

			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // invalidated — call 4
			await service.check(TEST_MODEL_ID, "alice", "/files", "write"); // invalidated — call 5
			await service.check(TEST_MODEL_ID, "bob", "/data", "read"); // still cached

			expect(spy).toHaveBeenCalledTimes(5);
		});

		test("removeRoleForSubject invalidates all keys for the subject but not other subjects", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // call 1
			await service.check(TEST_MODEL_ID, "alice", "/files", "write"); // call 2
			await service.check(TEST_MODEL_ID, "bob", "/data", "read"); // call 3

			await service.removeRoleForSubject(TEST_MODEL_ID, "alice", "admin");

			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // invalidated — call 4
			await service.check(TEST_MODEL_ID, "alice", "/files", "write"); // invalidated — call 5
			await service.check(TEST_MODEL_ID, "bob", "/data", "read"); // still cached

			expect(spy).toHaveBeenCalledTimes(5);
		});

		test("removeAllRolesForSubject invalidates all keys for the subject but not other subjects", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // call 1
			await service.check(TEST_MODEL_ID, "alice", "/files", "write"); // call 2
			await service.check(TEST_MODEL_ID, "bob", "/data", "read"); // call 3

			await service.removeAllRolesForSubject(TEST_MODEL_ID, "alice");

			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // invalidated — call 4
			await service.check(TEST_MODEL_ID, "alice", "/files", "write"); // invalidated — call 5
			await service.check(TEST_MODEL_ID, "bob", "/data", "read"); // still cached

			expect(spy).toHaveBeenCalledTimes(5);
		});

		test("addRoleInheritance invalidates all keys for the role but not other subjects", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await service.check(TEST_MODEL_ID, "editor", "/data", "read"); // call 1
			await service.check(TEST_MODEL_ID, "editor", "/files", "write"); // call 2
			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // call 3

			await service.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");

			await service.check(TEST_MODEL_ID, "editor", "/data", "read"); // invalidated — call 4
			await service.check(TEST_MODEL_ID, "editor", "/files", "write"); // invalidated — call 5
			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // still cached

			expect(spy).toHaveBeenCalledTimes(5);
		});

		test("removeRoleInheritance invalidates all keys for the role but not other subjects", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await service.check(TEST_MODEL_ID, "editor", "/data", "read"); // call 1
			await service.check(TEST_MODEL_ID, "editor", "/files", "write"); // call 2
			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // call 3

			await service.removeRoleInheritance(TEST_MODEL_ID, "editor", "viewer");

			await service.check(TEST_MODEL_ID, "editor", "/data", "read"); // invalidated — call 4
			await service.check(TEST_MODEL_ID, "editor", "/files", "write"); // invalidated — call 5
			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // still cached

			expect(spy).toHaveBeenCalledTimes(5);
		});

		test("role mutation invalidation is tenant-scoped", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantA" }, async () =>
				service.check(TEST_MODEL_ID, "alice", "/data", "read")
			);
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantB" }, async () =>
				service.check(TEST_MODEL_ID, "alice", "/data", "read")
			);
			expect(spy).toHaveBeenCalledTimes(2);

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantA" }, async () =>
				service.addRoleForSubject(TEST_MODEL_ID, "alice", "admin")
			);

			await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: "tenantA" },
				async () => service.check(TEST_MODEL_ID, "alice", "/data", "read") // tenantA invalidated
			);
			await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: "tenantB" },
				async () => service.check(TEST_MODEL_ID, "alice", "/data", "read") // tenantB still cached
			);

			expect(spy).toHaveBeenCalledTimes(3);
		});

		test("inheritance mutation invalidation is tenant-scoped", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantA" }, async () =>
				service.check(TEST_MODEL_ID, "editor", "/data", "read")
			);
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantB" }, async () =>
				service.check(TEST_MODEL_ID, "editor", "/data", "read")
			);
			expect(spy).toHaveBeenCalledTimes(2);

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantA" }, async () =>
				service.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer")
			);

			await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: "tenantA" },
				async () => service.check(TEST_MODEL_ID, "editor", "/data", "read") // tenantA invalidated
			);
			await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: "tenantB" },
				async () => service.check(TEST_MODEL_ID, "editor", "/data", "read") // tenantB still cached
			);

			expect(spy).toHaveBeenCalledTimes(3);
		});

		test("removePolicy re-check reflects revoked access on exact subject", async () => {
			await connector.addPolicy(TEST_MODEL_ID, "alice", "readData", "execute");
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });

			const before = await service.check(TEST_MODEL_ID, "alice", "readData", "execute");
			expect(before).toBe(true);

			await service.removePolicy(TEST_MODEL_ID, "alice", "readData", "execute");

			const after = await service.check(TEST_MODEL_ID, "alice", "readData", "execute");
			expect(after).toBe(false);
		});

		test("removeRoleForSubject re-check reflects revoked role", async () => {
			await connector.addPolicy(TEST_MODEL_ID, "admin", "readData", "execute");
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });

			const before = await service.check(TEST_MODEL_ID, "alice", "readData", "execute");
			expect(before).toBe(true);

			await service.removeRoleForSubject(TEST_MODEL_ID, "alice", "admin");

			const after = await service.check(TEST_MODEL_ID, "alice", "readData", "execute");
			expect(after).toBe(false);
		});

		test("build clears all cached results for the model", async () => {
			await connector.addPolicy(TEST_MODEL_ID, "alice", "readData", "execute");
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await service.check(TEST_MODEL_ID, "alice", "readData", "execute");
			await service.check(TEST_MODEL_ID, "alice", "readData", "execute");
			expect(spy).toHaveBeenCalledTimes(1);

			await service.build(TEST_MODEL_ID, { policies: [], roleInheritances: [] });

			await service.check(TEST_MODEL_ID, "alice", "readData", "execute");
			expect(spy).toHaveBeenCalledTimes(2);
		});
	});

	describe("start", () => {
		test("populates roles from migrationUserRoles and removes the SharedStore entry", async () => {
			SharedStore.set<{ identity: string; roles: string[]; contextIds: undefined }[]>(
				"migrationUserRoles",
				[
					{ identity: "user1", roles: ["admin", "editor"], contextIds: undefined },
					{ identity: "user2", roles: ["viewer"], contextIds: undefined }
				]
			);
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });

			await service.start();

			const user1Roles = await connector.getRolesForSubject("rest", "user1");
			const user2Roles = await connector.getRolesForSubject("rest", "user2");
			expect(user1Roles).toEqual(expect.arrayContaining(["admin", "editor"]));
			expect(user1Roles).toHaveLength(2);
			expect(user2Roles).toEqual(["viewer"]);
			expect(SharedStore.get("migrationUserRoles")).toBeUndefined();
		});

		test("populates roles within the correct tenant context when contextIds are provided", async () => {
			SharedStore.set<{ identity: string; roles: string[]; contextIds: { tenant: string } }[]>(
				"migrationUserRoles",
				[
					{
						identity: "user1",
						roles: ["admin"],
						contextIds: { [ContextIdKeys.Tenant]: "tenantA" }
					},
					{
						identity: "user2",
						roles: ["viewer"],
						contextIds: { [ContextIdKeys.Tenant]: "tenantB" }
					}
				]
			);

			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await service.start();

			const user1RolesInA = await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: "tenantA" },
				async () => connector.getRolesForSubject("rest", "user1")
			);
			const user2RolesInB = await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: "tenantB" },
				async () => connector.getRolesForSubject("rest", "user2")
			);

			expect(user1RolesInA).toEqual(["admin"]);
			expect(user2RolesInB).toEqual(["viewer"]);
			expect(SharedStore.get("migrationUserRoles")).toBeUndefined();
		});

		test("does not assign any roles when migrationUserRoles is absent", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "addRoleForSubject");

			await service.start();

			expect(spy).not.toHaveBeenCalled();
		});
	});

	describe("hasRoles", () => {
		test("returns empty array for empty input", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const result = await service.hasRoles(TEST_MODEL_ID, []);
			expect(result).toEqual([]);
		});

		test("returns false for a role that does not exist", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const result = await service.hasRoles(TEST_MODEL_ID, ["unknown"]);
			expect(result).toEqual([false]);
		});

		test("returns true for a role that exists", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			const result = await service.hasRoles(TEST_MODEL_ID, ["admin"]);
			expect(result).toEqual([true]);
		});

		test("returns results in input order for mixed existing and missing roles", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			const result = await service.hasRoles(TEST_MODEL_ID, ["admin", "missing"]);
			expect(result).toEqual([true, false]);
		});

		test("delegates to the connector", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "hasRoles");
			await service.hasRoles(TEST_MODEL_ID, ["admin"]);
			expect(spy).toHaveBeenCalledWith(TEST_MODEL_ID, ["admin"]);
		});
	});
});
