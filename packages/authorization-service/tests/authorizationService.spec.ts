// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import {
	AuthorizationConnectorFactory,
	type IAuthorizationConnector
} from "@twin.org/authorization-models";
import { ContextIdKeys, ContextIdStore } from "@twin.org/context";
import { AuthorizationService } from "../src/authorizationService.js";

const TEST_NAMESPACE = "test";

describe("AuthorizationService", () => {
	beforeEach(() => {
		AuthorizationConnectorFactory.register(
			TEST_NAMESPACE,
			() => ({ className: () => TEST_NAMESPACE }) as unknown as IAuthorizationConnector
		);
	});

	afterEach(() => {
		AuthorizationConnectorFactory.unregister(TEST_NAMESPACE);
	});

	test("Can create an instance", async () => {
		const service = new AuthorizationService();
		expect(service).toBeDefined();
	});

	describe("check cache", () => {
		function makeConnector(ns: string, checkResult: boolean): { callCount: number } {
			const tracker = { callCount: 0 };
			AuthorizationConnectorFactory.register(
				ns,
				() =>
					({
						className: () => ns,
						check: async () => {
							tracker.callCount++;
							return checkResult;
						},
						addPolicy: async () => {},
						removePolicy: async () => {},
						addRoleForSubject: async () => {},
						removeRoleForSubject: async () => {},
						removeAllRolesForSubject: async () => {},
						addRoleInheritance: async () => {},
						removeRoleInheritance: async () => {}
					}) as unknown as IAuthorizationConnector
			);
			return tracker;
		}

		afterEach(() => {
			for (const ns of AuthorizationConnectorFactory.names().filter(n => n.startsWith("cache-"))) {
				AuthorizationConnectorFactory.unregister(ns);
			}
		});

		test("returns cached result without calling connector again", async () => {
			const tracker = makeConnector("cache-hit", true);
			const service = new AuthorizationService({ config: { defaultNamespace: "cache-hit" } });

			const r1 = await service.check("alice", "/data", "read");
			const r2 = await service.check("alice", "/data", "read");

			expect(r1).toBe(true);
			expect(r2).toBe(true);
			expect(tracker.callCount).toBe(1);
		});

		test.each([
			[
				"addPolicy",
				"cache-addpolicy",
				"alice",
				async (svc: AuthorizationService) =>
					svc.addPolicy({
						subject: "alice",
						object: "/data",
						action: "read"
					})
			],
			[
				"removePolicy",
				"cache-removepolicy",
				"alice",
				async (svc: AuthorizationService) =>
					svc.removePolicy({
						subject: "alice",
						object: "/data",
						action: "read"
					})
			],
			[
				"addRoleForSubject",
				"cache-addrole",
				"alice",
				async (svc: AuthorizationService) => svc.addRoleForSubject("alice", "admin")
			],
			[
				"removeRoleForSubject",
				"cache-removerole",
				"alice",
				async (svc: AuthorizationService) => svc.removeRoleForSubject("alice", "admin")
			],
			[
				"removeAllRolesForSubject",
				"cache-removeallroles",
				"alice",
				async (svc: AuthorizationService) => svc.removeAllRolesForSubject("alice")
			],
			[
				"addRoleInheritance",
				"cache-addinheritance",
				"editor",
				async (svc: AuthorizationService) => svc.addRoleInheritance("editor", "viewer")
			],
			[
				"removeRoleInheritance",
				"cache-removeinheritance",
				"editor",
				async (svc: AuthorizationService) => svc.removeRoleInheritance("editor", "viewer")
			]
		])("invalidates cache after %s", async (label, ns, subject, mutate) => {
			const tracker = makeConnector(ns, false);
			const service = new AuthorizationService({ config: { defaultNamespace: ns } });

			await service.check(subject, "/data", "read");
			await mutate(service);
			await service.check(subject, "/data", "read");

			expect(tracker.callCount).toBe(2);
		});

		test("cache keys are tenant-aware", async () => {
			const tracker = makeConnector("cache-tenantkey", true);
			const service = new AuthorizationService({ config: { defaultNamespace: "cache-tenantkey" } });

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantA" }, async () =>
				service.check("alice", "/data", "read")
			);
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantB" }, async () =>
				service.check("alice", "/data", "read")
			);

			expect(tracker.callCount).toBe(2);
		});

		test("invalidation only affects the current tenant", async () => {
			const tracker = makeConnector("cache-tenantinvalidate", true);
			const service = new AuthorizationService({
				config: { defaultNamespace: "cache-tenantinvalidate" }
			});

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantA" }, async () =>
				service.check("alice", "/data", "read")
			);
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantB" }, async () =>
				service.check("alice", "/data", "read")
			);
			expect(tracker.callCount).toBe(2);

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantA" }, async () =>
				service.addPolicy({
					subject: "alice",
					object: "/data",
					action: "read"
				})
			);

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantA" }, async () =>
				service.check("alice", "/data", "read")
			);
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantB" }, async () =>
				service.check("alice", "/data", "read")
			);

			expect(tracker.callCount).toBe(3);
		});

		test("caches false results", async () => {
			const tracker = makeConnector("cache-false", false);
			const service = new AuthorizationService({ config: { defaultNamespace: "cache-false" } });

			const r1 = await service.check("alice", "/data", "read");
			const r2 = await service.check("alice", "/data", "read");

			expect(r1).toBe(false);
			expect(r2).toBe(false);
			expect(tracker.callCount).toBe(1);
		});

		test("addPolicy only invalidates the exact matching key", async () => {
			const tracker = makeConnector("cache-exact-addpolicy", true);
			const service = new AuthorizationService({
				config: { defaultNamespace: "cache-exact-addpolicy" }
			});

			await service.check("alice", "/data", "read");
			await service.check("alice", "/data", "write");

			await service.addPolicy({ subject: "alice", object: "/data", action: "read" });

			await service.check("alice", "/data", "read"); // invalidated — call 3
			await service.check("alice", "/data", "write"); // still cached

			expect(tracker.callCount).toBe(3);
		});

		test("removePolicy only invalidates the exact matching key", async () => {
			const tracker = makeConnector("cache-exact-removepolicy", true);
			const service = new AuthorizationService({
				config: { defaultNamespace: "cache-exact-removepolicy" }
			});

			await service.check("alice", "/data", "read");
			await service.check("alice", "/data", "write");

			await service.removePolicy({ subject: "alice", object: "/data", action: "read" });

			await service.check("alice", "/data", "read"); // invalidated — call 3
			await service.check("alice", "/data", "write"); // still cached

			expect(tracker.callCount).toBe(3);
		});

		test("addRoleForSubject invalidates all keys for the subject but not other subjects", async () => {
			const tracker = makeConnector("cache-subject-addrole", true);
			const service = new AuthorizationService({
				config: { defaultNamespace: "cache-subject-addrole" }
			});

			await service.check("alice", "/data", "read"); // call 1
			await service.check("alice", "/files", "write"); // call 2
			await service.check("bob", "/data", "read"); // call 3

			await service.addRoleForSubject("alice", "admin");

			await service.check("alice", "/data", "read"); // invalidated — call 4
			await service.check("alice", "/files", "write"); // invalidated — call 5
			await service.check("bob", "/data", "read"); // still cached

			expect(tracker.callCount).toBe(5);
		});

		test("removeRoleForSubject invalidates all keys for the subject but not other subjects", async () => {
			const tracker = makeConnector("cache-subject-removerole", true);
			const service = new AuthorizationService({
				config: { defaultNamespace: "cache-subject-removerole" }
			});

			await service.check("alice", "/data", "read");
			await service.check("alice", "/files", "write");
			await service.check("bob", "/data", "read");

			await service.removeRoleForSubject("alice", "admin");

			await service.check("alice", "/data", "read"); // invalidated
			await service.check("alice", "/files", "write"); // invalidated
			await service.check("bob", "/data", "read"); // still cached

			expect(tracker.callCount).toBe(5);
		});

		test("removeAllRolesForSubject invalidates all keys for the subject but not other subjects", async () => {
			const tracker = makeConnector("cache-subject-removeallroles", true);
			const service = new AuthorizationService({
				config: { defaultNamespace: "cache-subject-removeallroles" }
			});

			await service.check("alice", "/data", "read");
			await service.check("alice", "/files", "write");
			await service.check("bob", "/data", "read");

			await service.removeAllRolesForSubject("alice");

			await service.check("alice", "/data", "read"); // invalidated
			await service.check("alice", "/files", "write"); // invalidated
			await service.check("bob", "/data", "read"); // still cached

			expect(tracker.callCount).toBe(5);
		});

		test("addRoleInheritance invalidates all keys for the role but not other subjects", async () => {
			const tracker = makeConnector("cache-role-addinheritance", true);
			const service = new AuthorizationService({
				config: { defaultNamespace: "cache-role-addinheritance" }
			});

			await service.check("editor", "/data", "read"); // call 1
			await service.check("editor", "/files", "write"); // call 2
			await service.check("alice", "/data", "read"); // call 3

			await service.addRoleInheritance("editor", "viewer");

			await service.check("editor", "/data", "read"); // invalidated — call 4
			await service.check("editor", "/files", "write"); // invalidated — call 5
			await service.check("alice", "/data", "read"); // still cached

			expect(tracker.callCount).toBe(5);
		});

		test("removeRoleInheritance invalidates all keys for the role but not other subjects", async () => {
			const tracker = makeConnector("cache-role-removeinheritance", true);
			const service = new AuthorizationService({
				config: { defaultNamespace: "cache-role-removeinheritance" }
			});

			await service.check("editor", "/data", "read");
			await service.check("editor", "/files", "write");
			await service.check("alice", "/data", "read");

			await service.removeRoleInheritance("editor", "viewer");

			await service.check("editor", "/data", "read"); // invalidated
			await service.check("editor", "/files", "write"); // invalidated
			await service.check("alice", "/data", "read"); // still cached

			expect(tracker.callCount).toBe(5);
		});

		test("role mutation invalidation is tenant-scoped", async () => {
			const tracker = makeConnector("cache-tenant-role", true);
			const service = new AuthorizationService({
				config: { defaultNamespace: "cache-tenant-role" }
			});

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantA" }, async () =>
				service.check("alice", "/data", "read")
			);
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantB" }, async () =>
				service.check("alice", "/data", "read")
			);
			expect(tracker.callCount).toBe(2);

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantA" }, async () =>
				service.addRoleForSubject("alice", "admin")
			);

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantA" }, async () =>
				service.check("alice", "/data", "read")
			); // tenantA invalidated
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantB" }, async () =>
				service.check("alice", "/data", "read")
			); // tenantB still cached

			expect(tracker.callCount).toBe(3);
		});

		test("inheritance mutation invalidation is tenant-scoped", async () => {
			const tracker = makeConnector("cache-tenant-inheritance", true);
			const service = new AuthorizationService({
				config: { defaultNamespace: "cache-tenant-inheritance" }
			});

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantA" }, async () =>
				service.check("editor", "/data", "read")
			);
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantB" }, async () =>
				service.check("editor", "/data", "read")
			);
			expect(tracker.callCount).toBe(2);

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantA" }, async () =>
				service.addRoleInheritance("editor", "viewer")
			);

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantA" }, async () =>
				service.check("editor", "/data", "read")
			); // tenantA invalidated
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenantB" }, async () =>
				service.check("editor", "/data", "read")
			); // tenantB still cached

			expect(tracker.callCount).toBe(3);
		});
	});
});
