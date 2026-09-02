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
import {
	AuthorizationConnectorFactory,
	type IAuthorizationPolicy
} from "@twin.org/authorization-models";
import { ContextIdKeys, ContextIdStore } from "@twin.org/context";
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

		test("addPolicy invalidates only the current tenant cache for the subject", async () => {
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

			// Targeted invalidation: tenantA's alice entry evicted, tenantB's alice entry still cached
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

		test("addPolicy invalidates all cached check results for the subject", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // call 1
			await service.check(TEST_MODEL_ID, "alice", "/data", "write"); // call 2

			await service.addPolicy(TEST_MODEL_ID, "alice", "/data", "read");

			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // invalidated — call 3
			await service.check(TEST_MODEL_ID, "alice", "/data", "write"); // also invalidated — call 4

			expect(spy).toHaveBeenCalledTimes(4);
		});

		test("removePolicy invalidates all cached check results for the subject", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // call 1
			await service.check(TEST_MODEL_ID, "alice", "/data", "write"); // call 2

			await service.removePolicy(TEST_MODEL_ID, "alice", "/data", "read");

			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // invalidated — call 3
			await service.check(TEST_MODEL_ID, "alice", "/data", "write"); // also invalidated — call 4

			expect(spy).toHaveBeenCalledTimes(4);
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

		test("addPolicy invalidates cached results for subjects with the affected role but not unrelated subjects", async () => {
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // call 1
			await service.check(TEST_MODEL_ID, "bob", "/data", "read"); // call 2

			await service.addPolicy(TEST_MODEL_ID, "admin", "/data", "read");

			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // alice holds admin — invalidated — call 3
			await service.check(TEST_MODEL_ID, "bob", "/data", "read"); // bob has no admin role — still cached

			expect(spy).toHaveBeenCalledTimes(3);
		});

		test("removePolicy invalidates cached results for subjects with the affected role but not unrelated subjects", async () => {
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // call 1
			await service.check(TEST_MODEL_ID, "bob", "/data", "read"); // call 2

			await service.removePolicy(TEST_MODEL_ID, "admin", "/data", "read");

			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // alice holds admin — invalidated — call 3
			await service.check(TEST_MODEL_ID, "bob", "/data", "read"); // bob has no admin role — still cached

			expect(spy).toHaveBeenCalledTimes(3);
		});

		test("addPolicy invalidates cached results for transitive role holders", async () => {
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
			await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // call 1
			await service.check(TEST_MODEL_ID, "bob", "/data", "read"); // call 2

			await service.addPolicy(TEST_MODEL_ID, "viewer", "/data", "read");

			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // alice holds editor→viewer — invalidated — call 3
			await service.check(TEST_MODEL_ID, "bob", "/data", "read"); // bob unrelated — still cached

			expect(spy).toHaveBeenCalledTimes(3);
		});

		test("addRoleInheritance invalidates cached results for subjects of the child role but not unrelated subjects", async () => {
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // call 1
			await service.check(TEST_MODEL_ID, "bob", "/data", "read"); // call 2

			await service.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");

			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // alice holds editor — invalidated — call 3
			await service.check(TEST_MODEL_ID, "bob", "/data", "read"); // bob unrelated — still cached

			expect(spy).toHaveBeenCalledTimes(3);
		});

		test("removeRoleInheritance invalidates cached results for subjects of the child role but not unrelated subjects", async () => {
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
			await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // call 1
			await service.check(TEST_MODEL_ID, "bob", "/data", "read"); // call 2

			await service.removeRoleInheritance(TEST_MODEL_ID, "editor", "viewer");

			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // alice holds editor — invalidated — call 3
			await service.check(TEST_MODEL_ID, "bob", "/data", "read"); // bob unrelated — still cached

			expect(spy).toHaveBeenCalledTimes(3);
		});

		test("removePolicy invalidates cached results for transitive role holders", async () => {
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
			await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			const spy = vi.spyOn(connector, "check");

			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // call 1
			await service.check(TEST_MODEL_ID, "bob", "/data", "read"); // call 2

			await service.removePolicy(TEST_MODEL_ID, "viewer", "/data", "read");

			await service.check(TEST_MODEL_ID, "alice", "/data", "read"); // alice holds editor→viewer — invalidated — call 3
			await service.check(TEST_MODEL_ID, "bob", "/data", "read"); // bob unrelated — still cached

			expect(spy).toHaveBeenCalledTimes(3);
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

		test("addRoleInheritance invalidates only the current tenant cache for subjects of the child role", async () => {
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
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
				service.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer")
			);

			await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: "tenantA" },
				async () => service.check(TEST_MODEL_ID, "alice", "/data", "read") // tenantA invalidated
			);
			await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: "tenantB" },
				async () => service.check(TEST_MODEL_ID, "alice", "/data", "read") // tenantB still cached
			);

			// Targeted invalidation: tenantA's alice entry evicted, tenantB's alice entry still cached
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

		test("removePolicy re-check reflects revoked transitive access", async () => {
			await connector.addPolicy(TEST_MODEL_ID, "tenant:read", "tenantGet", "execute");
			await connector.addRoleInheritance(TEST_MODEL_ID, "tenant-admin", "tenant:read");
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "tenant-admin");
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });

			const before = await service.check(TEST_MODEL_ID, "alice", "tenantGet", "execute");
			expect(before).toBe(true);

			await service.removePolicy(TEST_MODEL_ID, "tenant:read", "tenantGet", "execute");

			const after = await service.check(TEST_MODEL_ID, "alice", "tenantGet", "execute");
			expect(after).toBe(false);
		});

		test("removeRoleInheritance re-check reflects revoked transitive access", async () => {
			await connector.addPolicy(TEST_MODEL_ID, "tenant:read", "tenantGet", "execute");
			await connector.addRoleInheritance(TEST_MODEL_ID, "tenant-admin", "tenant:read");
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "tenant-admin");
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });

			const before = await service.check(TEST_MODEL_ID, "alice", "tenantGet", "execute");
			expect(before).toBe(true);

			await service.removeRoleInheritance(TEST_MODEL_ID, "tenant-admin", "tenant:read");

			const after = await service.check(TEST_MODEL_ID, "alice", "tenantGet", "execute");
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

	describe("addRoleForSubject privilege escalation", () => {
		test("allows granting a role when no userId is in context", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await ContextIdStore.run({}, async () => {
				await expect(
					service.addRoleForSubject(TEST_MODEL_ID, "user-bob", "editor")
				).resolves.toBeUndefined();
			});
		});

		test("allows caller to grant a role they directly hold", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await connector.addRoleForSubject(TEST_MODEL_ID, "user-admin", "editor");
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await expect(
					service.addRoleForSubject(TEST_MODEL_ID, "user-bob", "editor")
				).resolves.toBeUndefined();
			});
		});

		test("allows caller to grant a role they do not hold", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await connector.addRoleForSubject(TEST_MODEL_ID, "user-admin", "editor");
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await expect(
					service.addRoleForSubject(TEST_MODEL_ID, "user-bob", "devops")
				).resolves.toBeUndefined();
			});
		});

		test("denies caller granting a direct child role of their own role", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await connector.addRoleInheritance(TEST_MODEL_ID, "super-editor", "editor");
			await connector.addRoleForSubject(TEST_MODEL_ID, "user-admin", "editor");
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await expect(
					service.addRoleForSubject(TEST_MODEL_ID, "user-bob", "super-editor")
				).rejects.toThrow();
			});
		});

		test("denies caller granting a transitive descendant role", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await connector.addRoleInheritance(TEST_MODEL_ID, "senior-editor", "editor");
			await connector.addRoleInheritance(TEST_MODEL_ID, "super-editor", "senior-editor");
			await connector.addRoleForSubject(TEST_MODEL_ID, "user-admin", "editor");
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await expect(
					service.addRoleForSubject(TEST_MODEL_ID, "user-bob", "super-editor")
				).rejects.toThrow();
			});
		});

		test("allows caller with multiple roles to grant a role that is not a descendant of any", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await connector.addRoleInheritance(TEST_MODEL_ID, "senior-editor", "editor");
			await connector.addRoleForSubject(TEST_MODEL_ID, "user-admin", "editor");
			await connector.addRoleForSubject(TEST_MODEL_ID, "user-admin", "auditor");
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await expect(
					service.addRoleForSubject(TEST_MODEL_ID, "user-bob", "devops")
				).resolves.toBeUndefined();
			});
		});
	});

	describe("addRoleInheritance escalation guard", () => {
		test("allows when no userId is in context", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await ContextIdStore.run({}, async () => {
				await expect(
					service.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer")
				).resolves.toBeUndefined();
			});
		});

		test("denies making caller role inherit from a descendant role", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await connector.addRoleInheritance(TEST_MODEL_ID, "super-editor", "editor");
			await connector.addRoleForSubject(TEST_MODEL_ID, "user-admin", "editor");
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await expect(
					service.addRoleInheritance(TEST_MODEL_ID, "editor", "super-editor")
				).rejects.toThrow();
			});
		});

		test("denies creating inheritance where the child role is a descendant of the caller", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await connector.addRoleInheritance(TEST_MODEL_ID, "super-editor", "editor");
			await connector.addRoleForSubject(TEST_MODEL_ID, "user-admin", "editor");
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await expect(
					service.addRoleInheritance(TEST_MODEL_ID, "super-editor", "viewer")
				).rejects.toThrow();
			});
		});

		test("allows inheritance between roles not in the forbidden set", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await connector.addRoleInheritance(TEST_MODEL_ID, "super-editor", "editor");
			await connector.addRoleForSubject(TEST_MODEL_ID, "user-admin", "editor");
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await expect(
					service.addRoleInheritance(TEST_MODEL_ID, "viewer", "reader")
				).resolves.toBeUndefined();
			});
		});
	});

	describe("addPolicy escalation guard", () => {
		test("allows when no userId is in context", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await ContextIdStore.run({}, async () => {
				await expect(
					service.addPolicy(TEST_MODEL_ID, "editor", "resource", "read")
				).resolves.toBeUndefined();
			});
		});

		test("denies adding a policy for the caller's own user id", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await connector.addRoleForSubject(TEST_MODEL_ID, "user-admin", "editor");
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await expect(
					service.addPolicy(TEST_MODEL_ID, "user-admin", "resource", "write")
				).rejects.toThrow();
			});
		});

		test("denies adding a policy for a role the caller directly holds", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await connector.addRoleForSubject(TEST_MODEL_ID, "user-admin", "editor");
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await expect(
					service.addPolicy(TEST_MODEL_ID, "editor", "resource", "write")
				).rejects.toThrow();
			});
		});

		test("denies adding a policy for an ancestor role the caller inherits from", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
			await connector.addRoleForSubject(TEST_MODEL_ID, "user-admin", "editor");
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await expect(
					service.addPolicy(TEST_MODEL_ID, "viewer", "resource", "write")
				).rejects.toThrow();
			});
		});

		test("allows adding a policy for an unrelated role", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await connector.addRoleForSubject(TEST_MODEL_ID, "user-admin", "editor");
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await expect(
					service.addPolicy(TEST_MODEL_ID, "devops", "resource", "read")
				).resolves.toBeUndefined();
			});
		});
	});

	describe("build system model guard", () => {
		test("allows build on system model when no userId is in context", async () => {
			const service = new AuthorizationService({
				config: { defaultNamespace: TEST_NAMESPACE, authorizationModelId: TEST_MODEL_ID }
			});
			await ContextIdStore.run({}, async () => {
				await expect(
					service.build(TEST_MODEL_ID, { policies: [], roleInheritances: [] })
				).resolves.toBeUndefined();
			});
		});

		test("denies build on system model when a userId is present in context", async () => {
			const service = new AuthorizationService({
				config: { defaultNamespace: TEST_NAMESPACE, authorizationModelId: TEST_MODEL_ID }
			});
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await expect(
					service.build(TEST_MODEL_ID, { policies: [], roleInheritances: [] })
				).rejects.toThrow();
			});
		});

		test("allows build on a non-system model without a userId", async () => {
			const service = new AuthorizationService({
				config: { defaultNamespace: TEST_NAMESPACE, authorizationModelId: "system" }
			});
			await ContextIdStore.run({}, async () => {
				await expect(
					service.build(TEST_MODEL_ID, { policies: [], roleInheritances: [] })
				).resolves.toBeUndefined();
			});
		});

		test("injects build policy for caller on first build of a non-system model", async () => {
			const service = new AuthorizationService({
				config: { defaultNamespace: TEST_NAMESPACE, authorizationModelId: "system" }
			});
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await service.build(TEST_MODEL_ID, {
					policies: [{ subject: "user-admin", object: "reports", action: "read" }],
					roleInheritances: []
				});
			});
			const { entities } = await connector.getAllPolicies(TEST_MODEL_ID, "user-admin");
			expect(
				entities.some(
					(p: IAuthorizationPolicy) => p.object === "authorization" && p.action === "build"
				)
			).toBe(true);
		});

		test("does not duplicate build policy when caller already includes it", async () => {
			const service = new AuthorizationService({
				config: { defaultNamespace: TEST_NAMESPACE, authorizationModelId: "system" }
			});
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await service.build(TEST_MODEL_ID, {
					policies: [{ subject: "user-admin", object: "authorization", action: "build" }],
					roleInheritances: []
				});
			});
			const { entities } = await connector.getAllPolicies(TEST_MODEL_ID, "user-admin");
			const buildPolicies = entities.filter(
				(p: IAuthorizationPolicy) => p.object === "authorization" && p.action === "build"
			);
			expect(buildPolicies).toHaveLength(1);
		});

		test("allows rebuild on existing non-system model when caller has build policy", async () => {
			const service = new AuthorizationService({
				config: { defaultNamespace: TEST_NAMESPACE, authorizationModelId: "system" }
			});
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await service.build(TEST_MODEL_ID, { policies: [], roleInheritances: [] });
				await expect(
					service.build(TEST_MODEL_ID, { policies: [], roleInheritances: [] })
				).resolves.toBeUndefined();
			});
		});

		test("denies rebuild on existing non-system model when caller lacks build policy", async () => {
			const service = new AuthorizationService({
				config: { defaultNamespace: TEST_NAMESPACE, authorizationModelId: "system" }
			});
			await connector.addPolicy(TEST_MODEL_ID, "user-owner", "authorization", "build");
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-other" }, async () => {
				await expect(
					service.build(TEST_MODEL_ID, { policies: [], roleInheritances: [] })
				).rejects.toThrow();
			});
		});
	});

	describe("build model guard (no authorizationModelId configured)", () => {
		test("allows build when no userId is in context", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await ContextIdStore.run({}, async () => {
				await expect(
					service.build(TEST_MODEL_ID, { policies: [], roleInheritances: [] })
				).resolves.toBeUndefined();
			});
		});

		test("allows first build with userId and injects build policy for the caller", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await service.build(TEST_MODEL_ID, {
					policies: [{ subject: "reader", object: "reports", action: "read" }],
					roleInheritances: []
				});
			});
			const { entities } = await connector.getAllPolicies(TEST_MODEL_ID, "user-admin");
			expect(
				entities.some(
					(p: IAuthorizationPolicy) => p.object === "authorization" && p.action === "build"
				)
			).toBe(true);
		});

		test("allows second build with userId when caller has the injected build policy", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await service.build(TEST_MODEL_ID, { policies: [], roleInheritances: [] });
				await expect(
					service.build(TEST_MODEL_ID, { policies: [], roleInheritances: [] })
				).resolves.toBeUndefined();
			});
		});

		test("denies second build with a different userId that has no build policy", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-owner" }, async () => {
				await service.build(TEST_MODEL_ID, { policies: [], roleInheritances: [] });
			});
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-other" }, async () => {
				await expect(
					service.build(TEST_MODEL_ID, { policies: [], roleInheritances: [] })
				).rejects.toThrow();
			});
		});
	});

	describe("removeRoleForSubject escalation guard", () => {
		test("allows removing a role that is not in the forbidden set", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await connector.addRoleInheritance(TEST_MODEL_ID, "super-editor", "editor");
			await connector.addRoleForSubject(TEST_MODEL_ID, "user-admin", "editor");
			await connector.addRoleForSubject(TEST_MODEL_ID, "user-bob", "viewer");
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await expect(
					service.removeRoleForSubject(TEST_MODEL_ID, "user-bob", "viewer")
				).resolves.toBeUndefined();
			});
		});

		test("denies removing a role that is a descendant of the caller's roles", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await connector.addRoleInheritance(TEST_MODEL_ID, "super-editor", "editor");
			await connector.addRoleForSubject(TEST_MODEL_ID, "user-admin", "editor");
			await connector.addRoleForSubject(TEST_MODEL_ID, "super-user", "super-editor");
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await expect(
					service.removeRoleForSubject(TEST_MODEL_ID, "super-user", "super-editor")
				).rejects.toThrow();
			});
		});
	});

	describe("removeAllRolesForSubject escalation guard", () => {
		test("denies removing the escalated privilege role from another subject", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await connector.addRoleForSubject(
				TEST_MODEL_ID,
				"user-global-admin",
				AuthorizationService.DEFAULT_ESCALATED_PRIVILEGE_ROLE
			);
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await expect(
					service.removeAllRolesForSubject(TEST_MODEL_ID, "user-global-admin")
				).rejects.toThrow();
			});
		});
	});

	describe("escalated privilege role assignment guard", () => {
		test("denies a role-less caller granting the escalated privilege role", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-proxy" }, async () => {
				await expect(
					service.addRoleForSubject(
						TEST_MODEL_ID,
						"user-admin",
						AuthorizationService.DEFAULT_ESCALATED_PRIVILEGE_ROLE
					)
				).rejects.toThrow();
			});
		});
	});

	describe("removeRoleInheritance escalation guard", () => {
		test("allows removing inheritance where the child role is not in the forbidden set", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await connector.addRoleInheritance(TEST_MODEL_ID, "super-editor", "editor");
			await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
			await connector.addRoleForSubject(TEST_MODEL_ID, "user-admin", "editor");
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await expect(
					service.removeRoleInheritance(TEST_MODEL_ID, "editor", "viewer")
				).resolves.toBeUndefined();
			});
		});

		test("denies removing inheritance where the child role is a descendant of the caller", async () => {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await connector.addRoleInheritance(TEST_MODEL_ID, "super-editor", "editor");
			await connector.addRoleForSubject(TEST_MODEL_ID, "user-admin", "editor");
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await expect(
					service.removeRoleInheritance(TEST_MODEL_ID, "super-editor", "editor")
				).rejects.toThrow();
			});
		});
	});

	describe("escalated privilege role", () => {
		const PRIV_ROLE = AuthorizationService.DEFAULT_ESCALATED_PRIVILEGE_ROLE;

		async function makePrivilegedService(): Promise<AuthorizationService> {
			const service = new AuthorizationService({ config: { defaultNamespace: TEST_NAMESPACE } });
			await connector.addRoleForSubject(TEST_MODEL_ID, "user-priv", PRIV_ROLE);
			return service;
		}

		test("holder can grant a descendant role that a normal caller cannot", async () => {
			const service = await makePrivilegedService();
			await connector.addRoleInheritance(TEST_MODEL_ID, "super-editor", "editor");
			await connector.addRoleForSubject(TEST_MODEL_ID, "user-priv", "editor");
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-priv" }, async () => {
				await expect(
					service.addRoleForSubject(TEST_MODEL_ID, "user-bob", "super-editor")
				).resolves.toBeUndefined();
			});
		});

		test("holder can add role inheritance involving a descendant role", async () => {
			const service = await makePrivilegedService();
			await connector.addRoleInheritance(TEST_MODEL_ID, "super-editor", "editor");
			await connector.addRoleForSubject(TEST_MODEL_ID, "user-priv", "editor");
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-priv" }, async () => {
				await expect(
					service.addRoleInheritance(TEST_MODEL_ID, "super-editor", "admin")
				).resolves.toBeUndefined();
			});
		});

		test("holder can add a policy for their own user ID", async () => {
			const service = await makePrivilegedService();
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-priv" }, async () => {
				await expect(
					service.addPolicy(TEST_MODEL_ID, "user-priv", "resource", "write")
				).resolves.toBeUndefined();
			});
		});

		test("holder can add a policy for a role they hold", async () => {
			const service = await makePrivilegedService();
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-priv" }, async () => {
				await expect(
					service.addPolicy(TEST_MODEL_ID, PRIV_ROLE, "resource", "write")
				).resolves.toBeUndefined();
			});
		});

		test("holder can remove a descendant role from another subject", async () => {
			const service = await makePrivilegedService();
			await connector.addRoleInheritance(TEST_MODEL_ID, "super-editor", "editor");
			await connector.addRoleForSubject(TEST_MODEL_ID, "user-priv", "editor");
			await connector.addRoleForSubject(TEST_MODEL_ID, "user-bob", "super-editor");
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-priv" }, async () => {
				await expect(
					service.removeRoleForSubject(TEST_MODEL_ID, "user-bob", "super-editor")
				).resolves.toBeUndefined();
			});
		});

		test("holder can remove role inheritance involving a descendant role", async () => {
			const service = await makePrivilegedService();
			await connector.addRoleInheritance(TEST_MODEL_ID, "super-editor", "editor");
			await connector.addRoleForSubject(TEST_MODEL_ID, "user-priv", "editor");
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-priv" }, async () => {
				await expect(
					service.removeRoleInheritance(TEST_MODEL_ID, "super-editor", "editor")
				).resolves.toBeUndefined();
			});
		});

		test("holder can build the system model", async () => {
			const service = new AuthorizationService({
				config: {
					defaultNamespace: TEST_NAMESPACE,
					authorizationModelId: TEST_MODEL_ID
				}
			});
			await connector.addRoleForSubject(TEST_MODEL_ID, "user-priv", PRIV_ROLE);
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-priv" }, async () => {
				await expect(
					service.build(TEST_MODEL_ID, { policies: [], roleInheritances: [] })
				).resolves.toBeUndefined();
			});
		});

		test("holder can rebuild an existing model without holding a build policy", async () => {
			const service = new AuthorizationService({
				config: { defaultNamespace: TEST_NAMESPACE, authorizationModelId: "system" }
			});
			await connector.addPolicy(TEST_MODEL_ID, "user-owner", "authorization", "build");
			await connector.addRoleForSubject(TEST_MODEL_ID, "user-priv", PRIV_ROLE);
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-priv" }, async () => {
				await expect(
					service.build(TEST_MODEL_ID, { policies: [], roleInheritances: [] })
				).resolves.toBeUndefined();
			});
		});

		test("non-holder with the same role name as escalated privilege but different config is still guarded", async () => {
			const service = new AuthorizationService({
				config: {
					defaultNamespace: TEST_NAMESPACE,
					escalatedPrivilegeRole: "super-god"
				}
			});
			await connector.addRoleInheritance(TEST_MODEL_ID, "super-editor", "editor");
			await connector.addRoleForSubject(TEST_MODEL_ID, "user-admin", "editor");
			await ContextIdStore.run({ [ContextIdKeys.User]: "user-admin" }, async () => {
				await expect(
					service.addRoleForSubject(TEST_MODEL_ID, "user-bob", "super-editor")
				).rejects.toThrow();
			});
		});
	});
});
