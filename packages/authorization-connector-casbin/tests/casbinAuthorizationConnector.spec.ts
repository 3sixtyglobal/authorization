// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { ContextIdKeys, ContextIdStore } from "@twin.org/context";
import {
	TEST_CASBIN_CLIENT_ID,
	TEST_CASBIN_CLIENT_SECRET,
	TEST_CASBIN_ENDPOINT
} from "./setupTestEnv.js";
import { CasbinAuthorizationConnector } from "../src/casbinAuthorizationConnector.js";

// This suite must be kept in sync with entityStorageAuthorizationConnector.spec.ts.
// Both connector implementations share the same contract; any test added, removed, or renamed
// in one file should be reflected in the other.

const TEST_TENANT_ID_A = "test-tenant-a";
const TEST_TENANT_ID_B = "test-tenant-b";
const TEST_MODEL_ID = "test-model";

describe("CasbinAuthorizationConnector", () => {
	let connector: CasbinAuthorizationConnector;

	async function cleanup(): Promise<void> {
		await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
			const { entities: policies } = await connector.getAllPolicies(TEST_MODEL_ID);
			for (const policy of policies) {
				await connector.removePolicy(TEST_MODEL_ID, policy.subject, policy.object, policy.action);
			}
			for (const subject of ["alice", "bob", "carol", "a", "b", "superuser"]) {
				await connector.removeAllRolesForSubject(TEST_MODEL_ID, subject);
			}
			for (const role of ["admin", "editor", "viewer", "superuser", "superAdmin", "a", "b"]) {
				const parents = await connector.getParentRoles(TEST_MODEL_ID, role);
				for (const parent of parents) {
					await connector.removeRoleInheritance(TEST_MODEL_ID, role, parent);
				}
			}
		});
	}

	beforeEach(async () => {
		connector = new CasbinAuthorizationConnector({
			config: {
				endpoint: TEST_CASBIN_ENDPOINT,
				clientId: TEST_CASBIN_CLIENT_ID,
				clientSecret: TEST_CASBIN_CLIENT_SECRET
			}
		});
		await cleanup();
	});

	afterEach(async () => {
		await cleanup();
	});

	test("can create an instance", async () => {
		await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
			expect(connector).toBeDefined();
			expect(connector.className()).toBe("CasbinAuthorizationConnector");
		});
	});

	describe("addPolicy / getAllPolicies", () => {
		test("stores a policy and retrieves it", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
				const { entities } = await connector.getAllPolicies(TEST_MODEL_ID);
				expect(entities).toHaveLength(1);
				expect(entities[0]).toEqual({ subject: "alice", object: "document", action: "read" });
			});
		});

		test("stores multiple distinct policies", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
				await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "write");
				await connector.addPolicy(TEST_MODEL_ID, "bob", "report", "read");
				const { entities } = await connector.getAllPolicies(TEST_MODEL_ID);
				expect(entities).toHaveLength(3);
			});
		});

		test("adding the same policy twice is idempotent", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
				await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
				const { entities } = await connector.getAllPolicies(TEST_MODEL_ID);
				expect(entities).toHaveLength(1);
			});
		});

		test("filters by subject when subject is provided", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
				await connector.addPolicy(TEST_MODEL_ID, "alice", "report", "write");
				await connector.addPolicy(TEST_MODEL_ID, "bob", "document", "read");
				const { entities } = await connector.getAllPolicies(TEST_MODEL_ID, "alice");
				expect(entities).toHaveLength(2);
				expect(entities.every(p => p.subject === "alice")).toBe(true);
			});
		});

		test("returns cursor when limit is reached", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "alice", "a", "read");
				await connector.addPolicy(TEST_MODEL_ID, "alice", "b", "read");
				await connector.addPolicy(TEST_MODEL_ID, "alice", "c", "read");
				const page1 = await connector.getAllPolicies(TEST_MODEL_ID, undefined, undefined, 2);
				expect(page1.entities).toHaveLength(2);
				expect(page1.cursor).toBeDefined();
				const page2 = await connector.getAllPolicies(TEST_MODEL_ID, undefined, page1.cursor, 2);
				expect(page2.entities).toHaveLength(1);
				expect(page2.cursor).toBeUndefined();
			});
		});

		test("cursor and subject filter can be combined", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "alice", "a", "read");
				await connector.addPolicy(TEST_MODEL_ID, "alice", "b", "read");
				await connector.addPolicy(TEST_MODEL_ID, "alice", "c", "read");
				await connector.addPolicy(TEST_MODEL_ID, "bob", "d", "read");
				const page1 = await connector.getAllPolicies(TEST_MODEL_ID, "alice", undefined, 2);
				expect(page1.entities).toHaveLength(2);
				expect(page1.entities.every(p => p.subject === "alice")).toBe(true);
				expect(page1.cursor).toBeDefined();
				const page2 = await connector.getAllPolicies(TEST_MODEL_ID, "alice", page1.cursor, 2);
				expect(page2.entities).toHaveLength(1);
				expect(page2.entities[0].subject).toBe("alice");
				expect(page2.cursor).toBeUndefined();
			});
		});

		test("returns no cursor when all results fit within the limit", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
				const { entities, cursor } = await connector.getAllPolicies(
					TEST_MODEL_ID,
					undefined,
					undefined,
					10
				);
				expect(entities).toHaveLength(1);
				expect(cursor).toBeUndefined();
			});
		});

		test("throws when subject is empty", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(connector.addPolicy(TEST_MODEL_ID, "", "document", "read")).rejects.toThrow();
			});
		});

		test("throws when object is empty", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(connector.addPolicy(TEST_MODEL_ID, "alice", "", "read")).rejects.toThrow();
			});
		});

		test("throws when action is empty", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(connector.addPolicy(TEST_MODEL_ID, "alice", "document", "")).rejects.toThrow();
			});
		});

		test("throws when subject contains the | separator", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(
					connector.addPolicy(TEST_MODEL_ID, "a|b", "document", "read")
				).rejects.toThrow();
			});
		});

		test("throws when object contains the | separator", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(
					connector.addPolicy(TEST_MODEL_ID, "alice", "doc|ument", "read")
				).rejects.toThrow();
			});
		});

		test("throws when action contains the | separator", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(
					connector.addPolicy(TEST_MODEL_ID, "alice", "document", "re|ad")
				).rejects.toThrow();
			});
		});

		test("a|b subject and b|c object do not collide with a subject and a b|c compound object", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
				await expect(connector.addPolicy(TEST_MODEL_ID, "a|b", "c", "execute")).rejects.toThrow();
				await expect(connector.check(TEST_MODEL_ID, "a", "b|c", "execute")).rejects.toThrow();
			});
		});
	});

	describe("removePolicy", () => {
		test("removes an existing policy", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
				await connector.removePolicy(TEST_MODEL_ID, "alice", "document", "read");
				const { entities } = await connector.getAllPolicies(TEST_MODEL_ID);
				expect(entities).toHaveLength(0);
			});
		});

		test("only removes the targeted policy", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
				await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "write");
				await connector.removePolicy(TEST_MODEL_ID, "alice", "document", "read");
				const { entities } = await connector.getAllPolicies(TEST_MODEL_ID);
				expect(entities).toHaveLength(1);
				expect(entities[0].action).toBe("write");
			});
		});

		test("removing a non-existent policy does not throw", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(
					connector.removePolicy(TEST_MODEL_ID, "alice", "document", "read")
				).resolves.toBeUndefined();
			});
		});
	});

	describe("getPoliciesForSubject", () => {
		test("returns only policies for the given subject", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
				await connector.addPolicy(TEST_MODEL_ID, "alice", "report", "write");
				await connector.addPolicy(TEST_MODEL_ID, "bob", "document", "read");
				const result = await connector.getPoliciesForSubject(TEST_MODEL_ID, "alice");
				expect(result.entities).toHaveLength(2);
				expect(result.entities.every(p => p.subject === "alice")).toBe(true);
			});
		});

		test("returns empty array when subject has no policies", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				const result = await connector.getPoliciesForSubject(TEST_MODEL_ID, "nobody");
				expect(result.entities).toHaveLength(0);
			});
		});

		test("throws when subject is empty", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(connector.getPoliciesForSubject(TEST_MODEL_ID, "")).rejects.toThrow();
			});
		});
	});

	describe("check", () => {
		test("returns true when a direct policy matches", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
				await expect(connector.check(TEST_MODEL_ID, "alice", "document", "read")).resolves.toBe(
					true
				);
			});
		});

		test("returns false when no policy matches the action", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
				await expect(connector.check(TEST_MODEL_ID, "alice", "document", "write")).resolves.toBe(
					false
				);
			});
		});

		test("returns false when no policy matches the object", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
				await expect(connector.check(TEST_MODEL_ID, "alice", "report", "read")).resolves.toBe(
					false
				);
			});
		});

		test("returns false when subject has no policies", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(connector.check(TEST_MODEL_ID, "nobody", "document", "read")).resolves.toBe(
					false
				);
			});
		});

		test("returns true when subject has a role with a matching policy", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "admin", "report", "delete");
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
				await expect(connector.check(TEST_MODEL_ID, "alice", "report", "delete")).resolves.toBe(
					true
				);
			});
		});

		test("returns false when role exists but has no matching policy", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "admin", "report", "delete");
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
				await expect(connector.check(TEST_MODEL_ID, "alice", "report", "delete")).resolves.toBe(
					false
				);
			});
		});

		test("returns true via single-level role inheritance", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "viewer", "document", "read");
				await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
				await expect(connector.check(TEST_MODEL_ID, "alice", "document", "read")).resolves.toBe(
					true
				);
			});
		});

		test("returns true via multi-level role inheritance chain", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "viewer", "document", "read");
				await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
				await connector.addRoleInheritance(TEST_MODEL_ID, "admin", "editor");
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
				await expect(connector.check(TEST_MODEL_ID, "alice", "document", "read")).resolves.toBe(
					true
				);
			});
		});

		test("returns false when inherited role has no matching policy", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "viewer", "document", "read");
				await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
				await expect(connector.check(TEST_MODEL_ID, "alice", "document", "write")).resolves.toBe(
					false
				);
			});
		});

		test("handles role cycles without looping forever", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleInheritance(TEST_MODEL_ID, "a", "b");
				await connector.addRoleInheritance(TEST_MODEL_ID, "b", "a");
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "a");
				await expect(connector.check(TEST_MODEL_ID, "alice", "document", "read")).resolves.toBe(
					false
				);
			});
		});

		test("throws when subject is empty", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(connector.check(TEST_MODEL_ID, "", "document", "read")).rejects.toThrow();
			});
		});

		test("throws when object is empty", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(connector.check(TEST_MODEL_ID, "alice", "", "read")).rejects.toThrow();
			});
		});

		test("throws when action is empty", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(connector.check(TEST_MODEL_ID, "alice", "document", "")).rejects.toThrow();
			});
		});
	});

	describe("role-based access control", () => {
		beforeEach(async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "tenantAdmin", "tenantCreate", "execute");
				await connector.addPolicy(TEST_MODEL_ID, "tenantAdmin", "tenantList", "execute");
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "tenantAdmin");
				await connector.addRoleForSubject(TEST_MODEL_ID, "bob", "tenantAdmin");
			});
		});

		test("all users assigned to a role can execute every action the role grants", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(
					connector.check(TEST_MODEL_ID, "alice", "tenantCreate", "execute")
				).resolves.toBe(true);
				await expect(
					connector.check(TEST_MODEL_ID, "alice", "tenantList", "execute")
				).resolves.toBe(true);
				await expect(
					connector.check(TEST_MODEL_ID, "bob", "tenantCreate", "execute")
				).resolves.toBe(true);
				await expect(connector.check(TEST_MODEL_ID, "bob", "tenantList", "execute")).resolves.toBe(
					true
				);
			});
		});

		test("a user without the role is denied access to role-gated resources", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(
					connector.check(TEST_MODEL_ID, "charlie", "tenantCreate", "execute")
				).resolves.toBe(false);
				await expect(
					connector.check(TEST_MODEL_ID, "charlie", "tenantList", "execute")
				).resolves.toBe(false);
			});
		});

		test("users cannot perform actions not covered by the role", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(
					connector.check(TEST_MODEL_ID, "alice", "tenantCreate", "delete")
				).resolves.toBe(false);
				await expect(
					connector.check(TEST_MODEL_ID, "bob", "tenantDelete", "execute")
				).resolves.toBe(false);
			});
		});

		test("removing one user from the role does not affect other users", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.removeRoleForSubject(TEST_MODEL_ID, "alice", "tenantAdmin");
				await expect(
					connector.check(TEST_MODEL_ID, "alice", "tenantCreate", "execute")
				).resolves.toBe(false);
				await expect(
					connector.check(TEST_MODEL_ID, "bob", "tenantCreate", "execute")
				).resolves.toBe(true);
			});
		});

		test("removing a policy revokes access for all users assigned to the role", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.removePolicy(TEST_MODEL_ID, "tenantAdmin", "tenantCreate", "execute");
				await expect(
					connector.check(TEST_MODEL_ID, "alice", "tenantCreate", "execute")
				).resolves.toBe(false);
				await expect(
					connector.check(TEST_MODEL_ID, "bob", "tenantCreate", "execute")
				).resolves.toBe(false);
				await expect(
					connector.check(TEST_MODEL_ID, "alice", "tenantList", "execute")
				).resolves.toBe(true);
			});
		});

		test("a user with multiple roles has combined access from all roles", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "auditor", "auditLog", "read");
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "auditor");
				await expect(
					connector.check(TEST_MODEL_ID, "alice", "tenantCreate", "execute")
				).resolves.toBe(true);
				await expect(connector.check(TEST_MODEL_ID, "alice", "auditLog", "read")).resolves.toBe(
					true
				);
				await expect(connector.check(TEST_MODEL_ID, "bob", "auditLog", "read")).resolves.toBe(
					false
				);
			});
		});
	});

	describe("addRoleForSubject / hasRoleForSubject", () => {
		test("assigns a role and confirms it exists", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
				await expect(connector.hasRoleForSubject(TEST_MODEL_ID, "alice", "admin")).resolves.toBe(
					true
				);
			});
		});

		test("returns false when role is not assigned to subject", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(connector.hasRoleForSubject(TEST_MODEL_ID, "alice", "admin")).resolves.toBe(
					false
				);
			});
		});

		test("assigning the same role twice is idempotent", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
				const roles = await connector.getRolesForSubject(TEST_MODEL_ID, "alice");
				expect(roles).toHaveLength(1);
			});
		});

		test("throws when subject is empty", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(connector.addRoleForSubject(TEST_MODEL_ID, "", "admin")).rejects.toThrow();
			});
		});

		test("throws when role is empty", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(connector.addRoleForSubject(TEST_MODEL_ID, "alice", "")).rejects.toThrow();
			});
		});

		test("throws when subject contains the | separator", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(connector.addRoleForSubject(TEST_MODEL_ID, "a|b", "admin")).rejects.toThrow();
			});
		});

		test("throws when role contains the | separator", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(
					connector.addRoleForSubject(TEST_MODEL_ID, "alice", "ad|min")
				).rejects.toThrow();
			});
		});
	});

	describe("removeRoleForSubject", () => {
		test("removes an assigned role", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
				await connector.removeRoleForSubject(TEST_MODEL_ID, "alice", "admin");
				await expect(connector.hasRoleForSubject(TEST_MODEL_ID, "alice", "admin")).resolves.toBe(
					false
				);
			});
		});

		test("only removes the targeted role, leaving others intact", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
				await connector.removeRoleForSubject(TEST_MODEL_ID, "alice", "editor");
				await expect(connector.hasRoleForSubject(TEST_MODEL_ID, "alice", "admin")).resolves.toBe(
					true
				);
				await expect(connector.hasRoleForSubject(TEST_MODEL_ID, "alice", "editor")).resolves.toBe(
					false
				);
			});
		});

		test("removing a non-existent role does not throw", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(
					connector.removeRoleForSubject(TEST_MODEL_ID, "alice", "admin")
				).resolves.toBeUndefined();
			});
		});
	});

	describe("removeAllRolesForSubject", () => {
		test("removes all roles from a subject", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
				await connector.removeAllRolesForSubject(TEST_MODEL_ID, "alice");
				const roles = await connector.getRolesForSubject(TEST_MODEL_ID, "alice");
				expect(roles).toHaveLength(0);
			});
		});

		test("does not affect roles of other subjects", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
				await connector.addRoleForSubject(TEST_MODEL_ID, "bob", "editor");
				await connector.removeAllRolesForSubject(TEST_MODEL_ID, "alice");
				const bobRoles = await connector.getRolesForSubject(TEST_MODEL_ID, "bob");
				expect(bobRoles).toHaveLength(1);
				expect(bobRoles[0]).toBe("editor");
			});
		});

		test("succeeds when subject has no roles", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(
					connector.removeAllRolesForSubject(TEST_MODEL_ID, "nobody")
				).resolves.toBeUndefined();
			});
		});
	});

	describe("getRolesForSubject", () => {
		test("returns all roles assigned to a subject", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
				const roles = await connector.getRolesForSubject(TEST_MODEL_ID, "alice");
				expect(roles).toHaveLength(2);
				expect(roles).toContain("admin");
				expect(roles).toContain("editor");
			});
		});

		test("returns empty array when subject has no roles", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				const roles = await connector.getRolesForSubject(TEST_MODEL_ID, "nobody");
				expect(roles).toHaveLength(0);
			});
		});

		test("throws when subject is empty", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(connector.getRolesForSubject(TEST_MODEL_ID, "")).rejects.toThrow();
			});
		});
	});

	describe("getSubjectsForRole", () => {
		test("returns all subjects with a given role", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
				await connector.addRoleForSubject(TEST_MODEL_ID, "bob", "admin");
				await connector.addRoleForSubject(TEST_MODEL_ID, "carol", "editor");
				const subjects = await connector.getSubjectsForRole(TEST_MODEL_ID, "admin");
				expect(subjects).toHaveLength(2);
				expect(subjects).toContain("alice");
				expect(subjects).toContain("bob");
			});
		});

		test("returns empty array when no subjects have the role", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				const subjects = await connector.getSubjectsForRole(TEST_MODEL_ID, "unknown-role");
				expect(subjects).toHaveLength(0);
			});
		});

		test("throws when role is empty", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(connector.getSubjectsForRole(TEST_MODEL_ID, "")).rejects.toThrow();
			});
		});
	});

	describe("addRoleInheritance / getParentRoles / getChildRoles", () => {
		test("defines inheritance and retrieves parent roles", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
				const parents = await connector.getParentRoles(TEST_MODEL_ID, "editor");
				expect(parents).toHaveLength(1);
				expect(parents[0]).toBe("viewer");
			});
		});

		test("defines inheritance and retrieves child roles", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
				const children = await connector.getChildRoles(TEST_MODEL_ID, "viewer");
				expect(children).toHaveLength(1);
				expect(children[0]).toBe("editor");
			});
		});

		test("a role can have multiple parents", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleInheritance(TEST_MODEL_ID, "superuser", "admin");
				await connector.addRoleInheritance(TEST_MODEL_ID, "superuser", "editor");
				const parents = await connector.getParentRoles(TEST_MODEL_ID, "superuser");
				expect(parents).toHaveLength(2);
				expect(parents).toContain("admin");
				expect(parents).toContain("editor");
			});
		});

		test("a role can have multiple children", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
				await connector.addRoleInheritance(TEST_MODEL_ID, "admin", "viewer");
				const children = await connector.getChildRoles(TEST_MODEL_ID, "viewer");
				expect(children).toHaveLength(2);
				expect(children).toContain("editor");
				expect(children).toContain("admin");
			});
		});

		test("adding the same inheritance twice is idempotent", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
				await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
				const parents = await connector.getParentRoles(TEST_MODEL_ID, "editor");
				expect(parents).toHaveLength(1);
			});
		});

		test("returns empty array when role has no parents", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				const parents = await connector.getParentRoles(TEST_MODEL_ID, "viewer");
				expect(parents).toHaveLength(0);
			});
		});

		test("returns empty array when role has no children", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				const children = await connector.getChildRoles(TEST_MODEL_ID, "admin");
				expect(children).toHaveLength(0);
			});
		});

		test("throws when role is empty for addRoleInheritance", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(connector.addRoleInheritance(TEST_MODEL_ID, "", "viewer")).rejects.toThrow();
			});
		});

		test("throws when inheritsFrom is empty for addRoleInheritance", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(connector.addRoleInheritance(TEST_MODEL_ID, "editor", "")).rejects.toThrow();
			});
		});

		test("throws when role contains the | separator for addRoleInheritance", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(
					connector.addRoleInheritance(TEST_MODEL_ID, "ed|itor", "viewer")
				).rejects.toThrow();
			});
		});

		test("throws when inheritsFrom contains the | separator for addRoleInheritance", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(
					connector.addRoleInheritance(TEST_MODEL_ID, "editor", "vie|wer")
				).rejects.toThrow();
			});
		});

		test("throws when role is empty for getParentRoles", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(connector.getParentRoles(TEST_MODEL_ID, "")).rejects.toThrow();
			});
		});

		test("throws when role is empty for getChildRoles", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(connector.getChildRoles(TEST_MODEL_ID, "")).rejects.toThrow();
			});
		});
	});

	describe("getAllRoles", () => {
		test("returns empty when no roles are assigned", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				const { roles } = await connector.getAllRoles(TEST_MODEL_ID);
				expect(roles).toHaveLength(0);
			});
		});

		test("returns distinct roles from role assignments", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
				await connector.addRoleForSubject(TEST_MODEL_ID, "bob", "admin");
				await connector.addRoleForSubject(TEST_MODEL_ID, "carol", "editor");
				const { roles } = await connector.getAllRoles(TEST_MODEL_ID);
				expect(roles).toHaveLength(2);
				expect(roles).toContain("admin");
				expect(roles).toContain("editor");
			});
		});

		test("returns distinct roles from role inheritance", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
				await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
				const { roles } = await connector.getAllRoles(TEST_MODEL_ID);
				expect(roles).toHaveLength(2);
				expect(roles).toContain("editor");
				expect(roles).toContain("viewer");
			});
		});

		test("returns cursor when limit is reached", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "viewer");
				const page1 = await connector.getAllRoles(TEST_MODEL_ID, undefined, 2);
				expect(page1.roles).toHaveLength(2);
				expect(page1.cursor).toBeDefined();
				const page2 = await connector.getAllRoles(TEST_MODEL_ID, page1.cursor, 2);
				expect(page2.roles).toHaveLength(1);
				expect(page2.cursor).toBeUndefined();
			});
		});

		test("returns no cursor when all roles fit within the limit", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
				const { roles, cursor } = await connector.getAllRoles(TEST_MODEL_ID, undefined, 10);
				expect(roles).toHaveLength(1);
				expect(cursor).toBeUndefined();
			});
		});

		test("roles are returned in alphabetical order", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "viewer");
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
				const { roles } = await connector.getAllRoles(TEST_MODEL_ID);
				expect(roles).toEqual(["admin", "editor", "viewer"]);
			});
		});

		test("lone addRoleInheritance reports only the parent role until the child is also assigned to a subject", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
				const { roles: rolesAfterInheritance } = await connector.getAllRoles(TEST_MODEL_ID);
				expect(rolesAfterInheritance).toContain("viewer");
				expect(rolesAfterInheritance).not.toContain("editor");

				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
				const { roles: rolesAfterAssignment } = await connector.getAllRoles(TEST_MODEL_ID);
				expect(rolesAfterAssignment).toContain("editor");
				expect(rolesAfterAssignment).toContain("viewer");
			});
		});

		test("role is removed when its last assignment is removed", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
				await connector.addRoleForSubject(TEST_MODEL_ID, "bob", "admin");
				await connector.removeRoleForSubject(TEST_MODEL_ID, "alice", "admin");
				const { roles } = await connector.getAllRoles(TEST_MODEL_ID);
				expect(roles).toContain("admin");
				await connector.removeRoleForSubject(TEST_MODEL_ID, "bob", "admin");
				const { roles: roles2 } = await connector.getAllRoles(TEST_MODEL_ID);
				expect(roles2).not.toContain("admin");
			});
		});

		test("role is kept when still referenced by inheritance after assignment is removed", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
				await connector.addRoleInheritance(TEST_MODEL_ID, "admin", "editor");
				await connector.removeRoleForSubject(TEST_MODEL_ID, "alice", "editor");
				const { roles } = await connector.getAllRoles(TEST_MODEL_ID);
				expect(roles).toContain("editor");
			});
		});

		test("role is removed when all assignments and inheritances are removed", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
				await connector.addRoleInheritance(TEST_MODEL_ID, "admin", "editor");
				await connector.removeRoleForSubject(TEST_MODEL_ID, "alice", "editor");
				await connector.removeRoleInheritance(TEST_MODEL_ID, "admin", "editor");
				const { roles } = await connector.getAllRoles(TEST_MODEL_ID);
				expect(roles).not.toContain("editor");
			});
		});

		test("role removed by removeAllRolesForSubject is no longer listed", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
				await connector.addRoleForSubject(TEST_MODEL_ID, "bob", "editor");
				await connector.removeAllRolesForSubject(TEST_MODEL_ID, "alice");
				const { roles } = await connector.getAllRoles(TEST_MODEL_ID);
				expect(roles).not.toContain("admin");
				expect(roles).toContain("editor");
			});
		});
	});

	describe("hasRoles", () => {
		test("returns empty array for empty input", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				const result = await connector.hasRoles(TEST_MODEL_ID, []);
				expect(result).toEqual([]);
			});
		});

		test("returns false for a role that does not exist", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				const result = await connector.hasRoles(TEST_MODEL_ID, ["unknown"]);
				expect(result).toEqual([false]);
			});
		});

		test("returns true for a role added via addRoleForSubject", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
				const result = await connector.hasRoles(TEST_MODEL_ID, ["admin"]);
				expect(result).toEqual([true]);
			});
		});

		test("returns true only for the parent role from a lone addRoleInheritance", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
				const result = await connector.hasRoles(TEST_MODEL_ID, ["editor", "viewer"]);
				expect(result).toEqual([false, true]);
			});
		});

		test("returns results in input order with mixed existing and missing roles", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
				const result = await connector.hasRoles(TEST_MODEL_ID, ["admin", "missing", "admin"]);
				expect(result).toEqual([true, false, true]);
			});
		});

		test("returns false after a role is removed and becomes unreferenced", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "temp");
				await connector.removeRoleForSubject(TEST_MODEL_ID, "alice", "temp");
				const result = await connector.hasRoles(TEST_MODEL_ID, ["temp"]);
				expect(result).toEqual([false]);
			});
		});

		test("throws when modelId is empty", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(connector.hasRoles("", ["admin"])).rejects.toThrow();
			});
		});
	});

	describe("removeRoleInheritance", () => {
		test("removes an inheritance relationship", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
				await connector.removeRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
				const parents = await connector.getParentRoles(TEST_MODEL_ID, "editor");
				expect(parents).toHaveLength(0);
			});
		});

		test("only removes the targeted inheritance, leaving others intact", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleInheritance(TEST_MODEL_ID, "admin", "editor");
				await connector.addRoleInheritance(TEST_MODEL_ID, "admin", "viewer");
				await connector.removeRoleInheritance(TEST_MODEL_ID, "admin", "viewer");
				const parents = await connector.getParentRoles(TEST_MODEL_ID, "admin");
				expect(parents).toHaveLength(1);
				expect(parents[0]).toBe("editor");
			});
		});

		test("removing a non-existent inheritance does not throw", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(
					connector.removeRoleInheritance(TEST_MODEL_ID, "editor", "viewer")
				).resolves.toBeUndefined();
			});
		});
	});

	describe("multi-tenant isolation", () => {
		async function cleanupTenant(tenantId: string): Promise<void> {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: tenantId }, async () => {
				const { entities: policies } = await connector.getAllPolicies(TEST_MODEL_ID);
				for (const policy of policies) {
					await connector.removePolicy(TEST_MODEL_ID, policy.subject, policy.object, policy.action);
				}
				for (const subject of ["alice", "bob"]) {
					await connector.removeAllRolesForSubject(TEST_MODEL_ID, subject);
				}
				for (const role of ["admin", "editor", "viewer"]) {
					const parents = await connector.getParentRoles(TEST_MODEL_ID, role);
					for (const parent of parents) {
						await connector.removeRoleInheritance(TEST_MODEL_ID, role, parent);
					}
				}
			});
		}

		beforeEach(async () => {
			await cleanupTenant(TEST_TENANT_ID_A);
			await cleanupTenant(TEST_TENANT_ID_B);
		});

		afterEach(async () => {
			await cleanupTenant(TEST_TENANT_ID_A);
			await cleanupTenant(TEST_TENANT_ID_B);
		});

		test("policies added under one tenant are not visible to another", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "alice", "/data", "read");
			});
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_B }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "alice", "/data", "write");
			});

			const tenantAPolicies = await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A },
				async () => {
					const { entities } = await connector.getAllPolicies(TEST_MODEL_ID);
					return entities;
				}
			);
			expect(tenantAPolicies).toHaveLength(1);
			expect(tenantAPolicies[0]).toMatchObject({
				subject: "alice",
				object: "/data",
				action: "read"
			});

			const tenantBPolicies = await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_B },
				async () => {
					const { entities } = await connector.getAllPolicies(TEST_MODEL_ID);
					return entities;
				}
			);
			expect(tenantBPolicies).toHaveLength(1);
			expect(tenantBPolicies[0]).toMatchObject({
				subject: "alice",
				object: "/data",
				action: "write"
			});
		});

		test("roles added under one tenant are not visible to another", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			});
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_B }, async () => {
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
			});

			const tenantARoles = await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A },
				async () => connector.getRolesForSubject(TEST_MODEL_ID, "alice")
			);
			expect(tenantARoles).toEqual(["admin"]);

			const tenantBRoles = await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_B },
				async () => connector.getRolesForSubject(TEST_MODEL_ID, "alice")
			);
			expect(tenantBRoles).toEqual(["editor"]);
		});

		test("check only evaluates policies within the current tenant", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "alice", "/data", "read");
			});

			const allowedInA = await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A },
				async () => connector.check(TEST_MODEL_ID, "alice", "/data", "read")
			);
			expect(allowedInA).toBe(true);

			const deniedInB = await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_B },
				async () => connector.check(TEST_MODEL_ID, "alice", "/data", "read")
			);
			expect(deniedInB).toBe(false);
		});

		test("the same subject can have different roles in different tenants", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
				await connector.addPolicy(TEST_MODEL_ID, "admin", "/admin", "write");
			});
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_B }, async () => {
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "viewer");
				await connector.addPolicy(TEST_MODEL_ID, "viewer", "/admin", "write");
			});

			const canWriteInA = await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A },
				async () => connector.check(TEST_MODEL_ID, "alice", "/admin", "write")
			);
			expect(canWriteInA).toBe(true);

			const canWriteInB = await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_B },
				async () => connector.check(TEST_MODEL_ID, "alice", "/admin", "write")
			);
			expect(canWriteInB).toBe(true);
		});

		test("getAllRoles returns only roles for the current tenant", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			});
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_B }, async () => {
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
			});

			const tenantARoles = await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A },
				async () => {
					const { roles } = await connector.getAllRoles(TEST_MODEL_ID);
					return roles;
				}
			);
			expect(tenantARoles).toEqual(["admin"]);

			const tenantBRoles = await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_B },
				async () => {
					const { roles } = await connector.getAllRoles(TEST_MODEL_ID);
					return roles;
				}
			);
			expect(tenantBRoles).toEqual(["editor"]);
		});

		test("each tenant has independent role inheritance", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "viewer", "/page", "read");
				await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
			});

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_B }, async () => {
				await expect(connector.check(TEST_MODEL_ID, "alice", "/page", "read")).resolves.toBe(false);
			});
		});
	});

	describe("organization scoping", () => {
		const ORG_A = "org-a";
		const ORG_B = "org-b";

		afterEach(async () => {
			for (const org of [ORG_A, ORG_B]) {
				await ContextIdStore.run(
					{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A, [ContextIdKeys.UserOrganization]: org },
					async () => {
						const { entities } = await connector.getAllPolicies(TEST_MODEL_ID);
						for (const policy of entities) {
							if (policy.organization === org) {
								await connector.removePolicy(
									TEST_MODEL_ID,
									policy.subject,
									policy.object,
									policy.action
								);
							}
						}
						await connector.removeAllRolesForSubject(TEST_MODEL_ID, "alice");
					}
				);
			}
		});

		test("an organization-scoped policy round-trips and is reported with its organization", async () => {
			await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A, [ContextIdKeys.UserOrganization]: ORG_A },
				async () => {
					await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
					const { entities } = await connector.getAllPolicies(TEST_MODEL_ID);
					expect(entities).toEqual([
						{ subject: "alice", object: "document", action: "read", organization: ORG_A }
					]);
				}
			);

			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				const { entities } = await connector.getAllPolicies(TEST_MODEL_ID);
				expect(entities).toEqual([]);
			});
		});

		test("a global policy matches under an organization context, a scoped one only its own", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
			});
			await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A, [ContextIdKeys.UserOrganization]: ORG_A },
				async () => {
					await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "write");
				}
			);

			await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A, [ContextIdKeys.UserOrganization]: ORG_A },
				async () => {
					await expect(connector.check(TEST_MODEL_ID, "alice", "document", "read")).resolves.toBe(
						true
					);
					await expect(connector.check(TEST_MODEL_ID, "alice", "document", "write")).resolves.toBe(
						true
					);
				}
			);
			await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A, [ContextIdKeys.UserOrganization]: ORG_B },
				async () => {
					await expect(connector.check(TEST_MODEL_ID, "alice", "document", "write")).resolves.toBe(
						false
					);
				}
			);
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await expect(connector.check(TEST_MODEL_ID, "alice", "document", "write")).resolves.toBe(
					false
				);
			});
		});

		test("an organization-scoped role assignment grants access through a global role policy", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "editor", "document", "write");
			});
			await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A, [ContextIdKeys.UserOrganization]: ORG_A },
				async () => {
					await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
				}
			);

			await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A, [ContextIdKeys.UserOrganization]: ORG_A },
				async () => {
					await expect(connector.check(TEST_MODEL_ID, "alice", "document", "write")).resolves.toBe(
						true
					);
					await expect(connector.hasRoleForSubject(TEST_MODEL_ID, "alice", "editor")).resolves.toBe(
						true
					);
				}
			);
			await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A, [ContextIdKeys.UserOrganization]: ORG_B },
				async () => {
					await expect(connector.check(TEST_MODEL_ID, "alice", "document", "write")).resolves.toBe(
						false
					);
					await expect(connector.hasRoleForSubject(TEST_MODEL_ID, "alice", "editor")).resolves.toBe(
						false
					);
				}
			);
		});

		test("removal under an organization context does not remove the global rule", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
			});

			await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A, [ContextIdKeys.UserOrganization]: ORG_A },
				async () => {
					await connector.removePolicy(TEST_MODEL_ID, "alice", "document", "read");
					await expect(connector.check(TEST_MODEL_ID, "alice", "document", "read")).resolves.toBe(
						true
					);
				}
			);
		});
	});
});
