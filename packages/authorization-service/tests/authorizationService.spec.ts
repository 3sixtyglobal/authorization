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
			await connector.addPolicy({ subject: "alice", object: "/data", action: "read" });
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			const r1 = await service.check("alice", "/data", "read");
			const r2 = await service.check("alice", "/data", "read");

			expect(r1).toBe(true);
			expect(r2).toBe(true);
			expect(spy).toHaveBeenCalledTimes(1);
		});

		test.each([
			[
				"addPolicy",
				"alice",
				async (svc: AuthorizationService) =>
					svc.addPolicy({ subject: "alice", object: "/data", action: "read" })
			],
			[
				"removePolicy",
				"alice",
				async (svc: AuthorizationService) =>
					svc.removePolicy({ subject: "alice", object: "/data", action: "read" })
			],
			[
				"addRoleForSubject",
				"alice",
				async (svc: AuthorizationService) => svc.addRoleForSubject("alice", "admin")
			],
			[
				"removeRoleForSubject",
				"alice",
				async (svc: AuthorizationService) => svc.removeRoleForSubject("alice", "admin")
			],
			[
				"removeAllRolesForSubject",
				"alice",
				async (svc: AuthorizationService) => svc.removeAllRolesForSubject("alice")
			],
			[
				"addRoleInheritance",
				"editor",
				async (svc: AuthorizationService) => svc.addRoleInheritance("editor", "viewer")
			],
			[
				"removeRoleInheritance",
				"editor",
				async (svc: AuthorizationService) => svc.removeRoleInheritance("editor", "viewer")
			]
		])("invalidates cache after %s", async (label, subject, mutate) => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await service.check(subject, "/data", "read");
			await mutate(service);
			await service.check(subject, "/data", "read");

			expect(spy).toHaveBeenCalledTimes(2);
		});

		test("cache keys are tenant-aware", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantA" }, async () =>
				service.check("alice", "/data", "read")
			);
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantB" }, async () =>
				service.check("alice", "/data", "read")
			);

			expect(spy).toHaveBeenCalledTimes(2);
		});

		test("invalidation only affects the current tenant", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantA" }, async () =>
				service.check("alice", "/data", "read")
			);
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantB" }, async () =>
				service.check("alice", "/data", "read")
			);
			expect(spy).toHaveBeenCalledTimes(2);

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantA" }, async () =>
				service.addPolicy({ subject: "alice", object: "/data", action: "read" })
			);

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantA" }, async () =>
				service.check("alice", "/data", "read")
			);
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantB" }, async () =>
				service.check("alice", "/data", "read")
			);

			expect(spy).toHaveBeenCalledTimes(3);
		});

		test("caches false results", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			const r1 = await service.check("alice", "/data", "read");
			const r2 = await service.check("alice", "/data", "read");

			expect(r1).toBe(false);
			expect(r2).toBe(false);
			expect(spy).toHaveBeenCalledTimes(1);
		});

		test("addPolicy only invalidates the exact matching key", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await service.check("alice", "/data", "read"); // call 1
			await service.check("alice", "/data", "write"); // call 2

			await service.addPolicy({ subject: "alice", object: "/data", action: "read" });

			await service.check("alice", "/data", "read"); // invalidated — call 3
			await service.check("alice", "/data", "write"); // still cached

			expect(spy).toHaveBeenCalledTimes(3);
		});

		test("removePolicy only invalidates the exact matching key", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await service.check("alice", "/data", "read"); // call 1
			await service.check("alice", "/data", "write"); // call 2

			await service.removePolicy({ subject: "alice", object: "/data", action: "read" });

			await service.check("alice", "/data", "read"); // invalidated — call 3
			await service.check("alice", "/data", "write"); // still cached

			expect(spy).toHaveBeenCalledTimes(3);
		});

		test("addRoleForSubject invalidates all keys for the subject but not other subjects", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await service.check("alice", "/data", "read"); // call 1
			await service.check("alice", "/files", "write"); // call 2
			await service.check("bob", "/data", "read"); // call 3

			await service.addRoleForSubject("alice", "admin");

			await service.check("alice", "/data", "read"); // invalidated — call 4
			await service.check("alice", "/files", "write"); // invalidated — call 5
			await service.check("bob", "/data", "read"); // still cached

			expect(spy).toHaveBeenCalledTimes(5);
		});

		test("removeRoleForSubject invalidates all keys for the subject but not other subjects", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await service.check("alice", "/data", "read"); // call 1
			await service.check("alice", "/files", "write"); // call 2
			await service.check("bob", "/data", "read"); // call 3

			await service.removeRoleForSubject("alice", "admin");

			await service.check("alice", "/data", "read"); // invalidated — call 4
			await service.check("alice", "/files", "write"); // invalidated — call 5
			await service.check("bob", "/data", "read"); // still cached

			expect(spy).toHaveBeenCalledTimes(5);
		});

		test("removeAllRolesForSubject invalidates all keys for the subject but not other subjects", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await service.check("alice", "/data", "read"); // call 1
			await service.check("alice", "/files", "write"); // call 2
			await service.check("bob", "/data", "read"); // call 3

			await service.removeAllRolesForSubject("alice");

			await service.check("alice", "/data", "read"); // invalidated — call 4
			await service.check("alice", "/files", "write"); // invalidated — call 5
			await service.check("bob", "/data", "read"); // still cached

			expect(spy).toHaveBeenCalledTimes(5);
		});

		test("addRoleInheritance invalidates all keys for the role but not other subjects", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await service.check("editor", "/data", "read"); // call 1
			await service.check("editor", "/files", "write"); // call 2
			await service.check("alice", "/data", "read"); // call 3

			await service.addRoleInheritance("editor", "viewer");

			await service.check("editor", "/data", "read"); // invalidated — call 4
			await service.check("editor", "/files", "write"); // invalidated — call 5
			await service.check("alice", "/data", "read"); // still cached

			expect(spy).toHaveBeenCalledTimes(5);
		});

		test("removeRoleInheritance invalidates all keys for the role but not other subjects", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await service.check("editor", "/data", "read"); // call 1
			await service.check("editor", "/files", "write"); // call 2
			await service.check("alice", "/data", "read"); // call 3

			await service.removeRoleInheritance("editor", "viewer");

			await service.check("editor", "/data", "read"); // invalidated — call 4
			await service.check("editor", "/files", "write"); // invalidated — call 5
			await service.check("alice", "/data", "read"); // still cached

			expect(spy).toHaveBeenCalledTimes(5);
		});

		test("role mutation invalidation is tenant-scoped", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantA" }, async () =>
				service.check("alice", "/data", "read")
			);
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantB" }, async () =>
				service.check("alice", "/data", "read")
			);
			expect(spy).toHaveBeenCalledTimes(2);

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantA" }, async () =>
				service.addRoleForSubject("alice", "admin")
			);

			await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: "tenantA" },
				async () => service.check("alice", "/data", "read") // tenantA invalidated
			);
			await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: "tenantB" },
				async () => service.check("alice", "/data", "read") // tenantB still cached
			);

			expect(spy).toHaveBeenCalledTimes(3);
		});

		test("inheritance mutation invalidation is tenant-scoped", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantA" }, async () =>
				service.check("editor", "/data", "read")
			);
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantB" }, async () =>
				service.check("editor", "/data", "read")
			);
			expect(spy).toHaveBeenCalledTimes(2);

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantA" }, async () =>
				service.addRoleInheritance("editor", "viewer")
			);

			await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: "tenantA" },
				async () => service.check("editor", "/data", "read") // tenantA invalidated
			);
			await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: "tenantB" },
				async () => service.check("editor", "/data", "read") // tenantB still cached
			);

			expect(spy).toHaveBeenCalledTimes(3);
		});
	});

	describe("checkAny", () => {
		test("returns false when subjects is empty", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await expect(service.checkAny([], "resource", "execute")).resolves.toBe(false);
		});

		test("returns true when a subject has a matching policy", async () => {
			await connector.addPolicy({ subject: "alice", object: "resource", action: "execute" });
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await expect(service.checkAny(["alice"], "resource", "execute")).resolves.toBe(true);
		});

		test("returns true when at least one of multiple subjects has a matching policy", async () => {
			await connector.addPolicy({ subject: "alice", object: "resource", action: "execute" });
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await expect(service.checkAny(["bob", "alice"], "resource", "execute")).resolves.toBe(true);
		});

		test("returns false when no subject has a matching policy", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await expect(service.checkAny(["alice", "bob"], "resource", "execute")).resolves.toBe(false);
		});

		test("caches each subject result so the connector is not called again on subsequent calls", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "checkAny");

			await service.checkAny(["alice", "bob"], "resource", "execute");
			await service.checkAny(["alice", "bob"], "resource", "execute");

			expect(spy).toHaveBeenCalledTimes(1);
		});

		test("returns true immediately when a subject is already cached as true", async () => {
			await connector.addPolicy({ subject: "alice", object: "resource", action: "execute" });
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "checkAny");

			await service.checkAny(["alice"], "resource", "execute");
			expect(spy).toHaveBeenCalledTimes(1);

			const result = await service.checkAny(["alice", "bob"], "resource", "execute");
			expect(result).toBe(true);
			expect(spy).toHaveBeenCalledTimes(1);
		});

		test("calls the connector only for subjects not already in the cache", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "checkAny");

			await service.checkAny(["alice"], "resource", "execute");
			await service.checkAny(["alice", "bob"], "resource", "execute");

			expect(spy).toHaveBeenCalledTimes(2);
			expect(spy.mock.calls[1][0]).toEqual(["bob"]);
		});
	});

	describe("start", () => {
		test("populates roles from migrationUserRoles and removes the SharedStore entry", async () => {
			SharedStore.set<{ [id: string]: string[] }>("migrationUserRoles", {
				user1: ["admin", "editor"],
				user2: ["viewer"]
			});
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });

			await service.start();

			const user1Roles = await connector.getRolesForSubject("user1");
			const user2Roles = await connector.getRolesForSubject("user2");
			expect(user1Roles).toEqual(expect.arrayContaining(["admin", "editor"]));
			expect(user1Roles).toHaveLength(2);
			expect(user2Roles).toEqual(["viewer"]);
			expect(SharedStore.get("migrationUserRoles")).toBeUndefined();
		});

		test("does not assign any roles when migrationUserRoles is absent", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "addRoleForSubject");

			await service.start();

			expect(spy).not.toHaveBeenCalled();
		});
	});
});
