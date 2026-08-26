// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { ContextIdKeys, ContextIdStore } from "@twin.org/context";
import { MemoryEntityStorageConnector } from "@twin.org/entity-storage-connector-memory";
import { EntityStorageConnectorFactory } from "@twin.org/entity-storage-models";
import { nameof } from "@twin.org/nameof";
import type { AuthorizationPolicy } from "../src/entities/authorizationPolicy.js";
import type { AuthorizationRoleAssignment } from "../src/entities/authorizationRoleAssignment.js";
import type { AuthorizationRoleInheritance } from "../src/entities/authorizationRoleInheritance.js";
import type { AuthorizationRoleName } from "../src/entities/authorizationRoleName.js";
import { EntityStorageAuthorizationConnector } from "../src/entityStorageAuthorizationConnector.js";
import { initSchema } from "../src/schema.js";

const TEST_TENANT_ID_A = "test-tenant-a";
const TEST_TENANT_ID_B = "test-tenant-b";
const TEST_MODEL_ID = "test-model";

describe("EntityStorageAuthorizationConnector", () => {
	let policyStorage: MemoryEntityStorageConnector<AuthorizationPolicy>;
	let roleStorage: MemoryEntityStorageConnector<AuthorizationRoleAssignment>;
	let inheritanceStorage: MemoryEntityStorageConnector<AuthorizationRoleInheritance>;
	let roleNameStorage: MemoryEntityStorageConnector<AuthorizationRoleName>;
	let connector: EntityStorageAuthorizationConnector;

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
	});

	afterEach(async () => {
		await policyStorage.teardown();
		await roleStorage.teardown();
		await inheritanceStorage.teardown();
		await roleNameStorage.teardown();
	});

	test("can create an instance", () => {
		expect(connector).toBeDefined();
		expect(connector.className()).toBe("EntityStorageAuthorizationConnector");
	});

	describe("addPolicy / getAllPolicies", () => {
		test("stores a policy and retrieves it", async () => {
			await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
			const { entities } = await connector.getAllPolicies(TEST_MODEL_ID);
			expect(entities).toHaveLength(1);
			expect(entities[0]).toEqual({ subject: "alice", object: "document", action: "read" });
		});

		test("stores multiple distinct policies", async () => {
			await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
			await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "write");
			await connector.addPolicy(TEST_MODEL_ID, "bob", "report", "read");
			const { entities } = await connector.getAllPolicies(TEST_MODEL_ID);
			expect(entities).toHaveLength(3);
		});

		test("adding the same policy twice is idempotent", async () => {
			await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
			await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
			const { entities } = await connector.getAllPolicies(TEST_MODEL_ID);
			expect(entities).toHaveLength(1);
		});

		test("filters by subject when subject is provided", async () => {
			await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
			await connector.addPolicy(TEST_MODEL_ID, "bob", "report", "read");
			const { entities } = await connector.getAllPolicies(TEST_MODEL_ID, "alice");
			expect(entities).toHaveLength(1);
			expect(entities[0].subject).toBe("alice");
		});

		test("returns cursor when limit is reached", async () => {
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

		test("cursor and subject filter can be combined", async () => {
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

		test("returns no cursor when all results fit within the limit", async () => {
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

		test("throws when subject is empty", async () => {
			await expect(connector.addPolicy(TEST_MODEL_ID, "", "document", "read")).rejects.toThrow();
		});

		test("throws when object is empty", async () => {
			await expect(connector.addPolicy(TEST_MODEL_ID, "alice", "", "read")).rejects.toThrow();
		});

		test("throws when action is empty", async () => {
			await expect(connector.addPolicy(TEST_MODEL_ID, "alice", "document", "")).rejects.toThrow();
		});
	});

	describe("removePolicy", () => {
		test("removes an existing policy", async () => {
			await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
			await connector.removePolicy(TEST_MODEL_ID, "alice", "document", "read");
			const { entities } = await connector.getAllPolicies(TEST_MODEL_ID);
			expect(entities).toHaveLength(0);
		});

		test("only removes the targeted policy", async () => {
			await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
			await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "write");
			await connector.removePolicy(TEST_MODEL_ID, "alice", "document", "read");
			const { entities } = await connector.getAllPolicies(TEST_MODEL_ID);
			expect(entities).toHaveLength(1);
			expect(entities[0].action).toBe("write");
		});

		test("removing a non-existent policy does not throw", async () => {
			await expect(
				connector.removePolicy(TEST_MODEL_ID, "alice", "document", "read")
			).resolves.toBeUndefined();
		});
	});

	describe("getPoliciesForSubject", () => {
		test("returns only policies for the given subject", async () => {
			await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
			await connector.addPolicy(TEST_MODEL_ID, "alice", "report", "write");
			await connector.addPolicy(TEST_MODEL_ID, "bob", "document", "read");

			const result = await connector.getPoliciesForSubject(TEST_MODEL_ID, "alice");
			expect(result.entities).toHaveLength(2);
			expect(result.entities.every(p => p.subject === "alice")).toBe(true);
		});

		test("returns empty array when subject has no policies", async () => {
			const result = await connector.getPoliciesForSubject(TEST_MODEL_ID, "nobody");
			expect(result.entities).toHaveLength(0);
		});

		test("throws when subject is empty", async () => {
			await expect(connector.getPoliciesForSubject(TEST_MODEL_ID, "")).rejects.toThrow();
		});
	});

	describe("check", () => {
		test("returns true when a direct policy matches", async () => {
			await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
			await expect(connector.check(TEST_MODEL_ID, "alice", "document", "read")).resolves.toBe(true);
		});

		test("returns false when no policy matches the action", async () => {
			await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
			await expect(connector.check(TEST_MODEL_ID, "alice", "document", "write")).resolves.toBe(
				false
			);
		});

		test("returns false when no policy matches the object", async () => {
			await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
			await expect(connector.check(TEST_MODEL_ID, "alice", "report", "read")).resolves.toBe(false);
		});

		test("returns false when subject has no policies", async () => {
			await expect(connector.check(TEST_MODEL_ID, "nobody", "document", "read")).resolves.toBe(
				false
			);
		});

		test("returns true when subject has a role with a matching policy", async () => {
			await connector.addPolicy(TEST_MODEL_ID, "admin", "report", "delete");
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			await expect(connector.check(TEST_MODEL_ID, "alice", "report", "delete")).resolves.toBe(true);
		});

		test("returns false when role exists but has no matching policy", async () => {
			await connector.addPolicy(TEST_MODEL_ID, "admin", "report", "delete");
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
			await expect(connector.check(TEST_MODEL_ID, "alice", "report", "delete")).resolves.toBe(
				false
			);
		});

		test("returns true via single-level role inheritance", async () => {
			await connector.addPolicy(TEST_MODEL_ID, "viewer", "document", "read");
			await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
			await expect(connector.check(TEST_MODEL_ID, "alice", "document", "read")).resolves.toBe(true);
		});

		test("returns true via multi-level role inheritance chain", async () => {
			await connector.addPolicy(TEST_MODEL_ID, "viewer", "document", "read");
			await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
			await connector.addRoleInheritance(TEST_MODEL_ID, "admin", "editor");
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			await expect(connector.check(TEST_MODEL_ID, "alice", "document", "read")).resolves.toBe(true);
		});

		test("returns false when inherited role has no matching policy", async () => {
			await connector.addPolicy(TEST_MODEL_ID, "viewer", "document", "read");
			await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
			await expect(connector.check(TEST_MODEL_ID, "alice", "document", "write")).resolves.toBe(
				false
			);
		});

		test("handles role cycles without looping forever", async () => {
			await connector.addRoleInheritance(TEST_MODEL_ID, "a", "b");
			await connector.addRoleInheritance(TEST_MODEL_ID, "b", "a");
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "a");
			await expect(connector.check(TEST_MODEL_ID, "alice", "document", "read")).resolves.toBe(
				false
			);
		});

		test("throws when subject is empty", async () => {
			await expect(connector.check(TEST_MODEL_ID, "", "document", "read")).rejects.toThrow();
		});

		test("throws when object is empty", async () => {
			await expect(connector.check(TEST_MODEL_ID, "alice", "", "read")).rejects.toThrow();
		});

		test("throws when action is empty", async () => {
			await expect(connector.check(TEST_MODEL_ID, "alice", "document", "")).rejects.toThrow();
		});
	});

	describe("role-based access control", () => {
		beforeEach(async () => {
			await connector.addPolicy(TEST_MODEL_ID, "tenantAdmin", "tenantCreate", "execute");
			await connector.addPolicy(TEST_MODEL_ID, "tenantAdmin", "tenantList", "execute");
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "tenantAdmin");
			await connector.addRoleForSubject(TEST_MODEL_ID, "bob", "tenantAdmin");
		});

		test("all users assigned to a role can execute every action the role grants", async () => {
			await expect(
				connector.check(TEST_MODEL_ID, "alice", "tenantCreate", "execute")
			).resolves.toBe(true);
			await expect(connector.check(TEST_MODEL_ID, "alice", "tenantList", "execute")).resolves.toBe(
				true
			);
			await expect(connector.check(TEST_MODEL_ID, "bob", "tenantCreate", "execute")).resolves.toBe(
				true
			);
			await expect(connector.check(TEST_MODEL_ID, "bob", "tenantList", "execute")).resolves.toBe(
				true
			);
		});

		test("a user without the role is denied access to role-gated resources", async () => {
			await expect(
				connector.check(TEST_MODEL_ID, "charlie", "tenantCreate", "execute")
			).resolves.toBe(false);
			await expect(
				connector.check(TEST_MODEL_ID, "charlie", "tenantList", "execute")
			).resolves.toBe(false);
		});

		test("users cannot perform actions not covered by the role", async () => {
			await expect(connector.check(TEST_MODEL_ID, "alice", "tenantCreate", "delete")).resolves.toBe(
				false
			);
			await expect(connector.check(TEST_MODEL_ID, "bob", "tenantDelete", "execute")).resolves.toBe(
				false
			);
		});

		test("removing one user from the role does not affect other users", async () => {
			await connector.removeRoleForSubject(TEST_MODEL_ID, "alice", "tenantAdmin");
			await expect(
				connector.check(TEST_MODEL_ID, "alice", "tenantCreate", "execute")
			).resolves.toBe(false);
			await expect(connector.check(TEST_MODEL_ID, "bob", "tenantCreate", "execute")).resolves.toBe(
				true
			);
		});

		test("removing a policy revokes access for all users assigned to the role", async () => {
			await connector.removePolicy(TEST_MODEL_ID, "tenantAdmin", "tenantCreate", "execute");
			await expect(
				connector.check(TEST_MODEL_ID, "alice", "tenantCreate", "execute")
			).resolves.toBe(false);
			await expect(connector.check(TEST_MODEL_ID, "bob", "tenantCreate", "execute")).resolves.toBe(
				false
			);
			await expect(connector.check(TEST_MODEL_ID, "alice", "tenantList", "execute")).resolves.toBe(
				true
			);
		});

		test("a user with multiple roles has combined access from all roles", async () => {
			await connector.addPolicy(TEST_MODEL_ID, "auditor", "auditLog", "read");
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "auditor");
			await expect(
				connector.check(TEST_MODEL_ID, "alice", "tenantCreate", "execute")
			).resolves.toBe(true);
			await expect(connector.check(TEST_MODEL_ID, "alice", "auditLog", "read")).resolves.toBe(true);
			await expect(connector.check(TEST_MODEL_ID, "bob", "auditLog", "read")).resolves.toBe(false);
		});
	});

	describe("addRoleForSubject / hasRoleForSubject", () => {
		test("assigns a role and confirms it exists", async () => {
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			await expect(connector.hasRoleForSubject(TEST_MODEL_ID, "alice", "admin")).resolves.toBe(
				true
			);
		});

		test("returns false when role is not assigned to subject", async () => {
			await expect(connector.hasRoleForSubject(TEST_MODEL_ID, "alice", "admin")).resolves.toBe(
				false
			);
		});

		test("assigning the same role twice is idempotent", async () => {
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			const roles = await connector.getRolesForSubject(TEST_MODEL_ID, "alice");
			expect(roles).toHaveLength(1);
		});

		test("throws when subject is empty", async () => {
			await expect(connector.addRoleForSubject(TEST_MODEL_ID, "", "admin")).rejects.toThrow();
		});

		test("throws when role is empty", async () => {
			await expect(connector.addRoleForSubject(TEST_MODEL_ID, "alice", "")).rejects.toThrow();
		});
	});

	describe("removeRoleForSubject", () => {
		test("removes an assigned role", async () => {
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			await connector.removeRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			await expect(connector.hasRoleForSubject(TEST_MODEL_ID, "alice", "admin")).resolves.toBe(
				false
			);
		});

		test("only removes the targeted role, leaving others intact", async () => {
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

		test("removing a non-existent role does not throw", async () => {
			await expect(
				connector.removeRoleForSubject(TEST_MODEL_ID, "alice", "admin")
			).resolves.toBeUndefined();
		});
	});

	describe("removeAllRolesForSubject", () => {
		test("removes all roles from a subject", async () => {
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
			await connector.removeAllRolesForSubject(TEST_MODEL_ID, "alice");
			const roles = await connector.getRolesForSubject(TEST_MODEL_ID, "alice");
			expect(roles).toHaveLength(0);
		});

		test("does not affect roles of other subjects", async () => {
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			await connector.addRoleForSubject(TEST_MODEL_ID, "bob", "editor");
			await connector.removeAllRolesForSubject(TEST_MODEL_ID, "alice");
			const bobRoles = await connector.getRolesForSubject(TEST_MODEL_ID, "bob");
			expect(bobRoles).toHaveLength(1);
			expect(bobRoles[0]).toBe("editor");
		});

		test("succeeds when subject has no roles", async () => {
			await expect(
				connector.removeAllRolesForSubject(TEST_MODEL_ID, "nobody")
			).resolves.toBeUndefined();
		});
	});

	describe("getRolesForSubject", () => {
		test("returns all roles assigned to a subject", async () => {
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
			const roles = await connector.getRolesForSubject(TEST_MODEL_ID, "alice");
			expect(roles).toHaveLength(2);
			expect(roles).toContain("admin");
			expect(roles).toContain("editor");
		});

		test("returns empty array when subject has no roles", async () => {
			const roles = await connector.getRolesForSubject(TEST_MODEL_ID, "nobody");
			expect(roles).toHaveLength(0);
		});

		test("throws when subject is empty", async () => {
			await expect(connector.getRolesForSubject(TEST_MODEL_ID, "")).rejects.toThrow();
		});
	});

	describe("getSubjectsForRole", () => {
		test("returns all subjects with a given role", async () => {
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			await connector.addRoleForSubject(TEST_MODEL_ID, "bob", "admin");
			await connector.addRoleForSubject(TEST_MODEL_ID, "carol", "editor");
			const subjects = await connector.getSubjectsForRole(TEST_MODEL_ID, "admin");
			expect(subjects).toHaveLength(2);
			expect(subjects).toContain("alice");
			expect(subjects).toContain("bob");
		});

		test("returns empty array when no subjects have the role", async () => {
			const subjects = await connector.getSubjectsForRole(TEST_MODEL_ID, "unknown-role");
			expect(subjects).toHaveLength(0);
		});

		test("throws when role is empty", async () => {
			await expect(connector.getSubjectsForRole(TEST_MODEL_ID, "")).rejects.toThrow();
		});
	});

	describe("addRoleInheritance / getParentRoles / getChildRoles", () => {
		test("defines inheritance and retrieves parent roles", async () => {
			await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
			const parents = await connector.getParentRoles(TEST_MODEL_ID, "editor");
			expect(parents).toHaveLength(1);
			expect(parents[0]).toBe("viewer");
		});

		test("defines inheritance and retrieves child roles", async () => {
			await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
			const children = await connector.getChildRoles(TEST_MODEL_ID, "viewer");
			expect(children).toHaveLength(1);
			expect(children[0]).toBe("editor");
		});

		test("a role can have multiple parents", async () => {
			await connector.addRoleInheritance(TEST_MODEL_ID, "superuser", "admin");
			await connector.addRoleInheritance(TEST_MODEL_ID, "superuser", "editor");
			const parents = await connector.getParentRoles(TEST_MODEL_ID, "superuser");
			expect(parents).toHaveLength(2);
			expect(parents).toContain("admin");
			expect(parents).toContain("editor");
		});

		test("a role can have multiple children", async () => {
			await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
			await connector.addRoleInheritance(TEST_MODEL_ID, "admin", "viewer");
			const children = await connector.getChildRoles(TEST_MODEL_ID, "viewer");
			expect(children).toHaveLength(2);
			expect(children).toContain("editor");
			expect(children).toContain("admin");
		});

		test("adding the same inheritance twice is idempotent", async () => {
			await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
			await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
			const parents = await connector.getParentRoles(TEST_MODEL_ID, "editor");
			expect(parents).toHaveLength(1);
		});

		test("returns empty array when role has no parents", async () => {
			const parents = await connector.getParentRoles(TEST_MODEL_ID, "viewer");
			expect(parents).toHaveLength(0);
		});

		test("returns empty array when role has no children", async () => {
			const children = await connector.getChildRoles(TEST_MODEL_ID, "admin");
			expect(children).toHaveLength(0);
		});

		test("throws when role is empty for addRoleInheritance", async () => {
			await expect(connector.addRoleInheritance(TEST_MODEL_ID, "", "viewer")).rejects.toThrow();
		});

		test("throws when inheritsFrom is empty for addRoleInheritance", async () => {
			await expect(connector.addRoleInheritance(TEST_MODEL_ID, "editor", "")).rejects.toThrow();
		});

		test("throws when role is empty for getParentRoles", async () => {
			await expect(connector.getParentRoles(TEST_MODEL_ID, "")).rejects.toThrow();
		});

		test("throws when role is empty for getChildRoles", async () => {
			await expect(connector.getChildRoles(TEST_MODEL_ID, "")).rejects.toThrow();
		});
	});

	describe("getAllRoles", () => {
		test("returns empty when no roles are assigned", async () => {
			const { roles } = await connector.getAllRoles(TEST_MODEL_ID);
			expect(roles).toHaveLength(0);
		});

		test("returns distinct roles from role assignments", async () => {
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			await connector.addRoleForSubject(TEST_MODEL_ID, "bob", "admin");
			await connector.addRoleForSubject(TEST_MODEL_ID, "carol", "editor");
			const { roles } = await connector.getAllRoles(TEST_MODEL_ID);
			expect(roles).toHaveLength(2);
			expect(roles).toContain("admin");
			expect(roles).toContain("editor");
		});

		test("returns distinct roles from role inheritance", async () => {
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
			await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
			const { roles } = await connector.getAllRoles(TEST_MODEL_ID);
			expect(roles).toHaveLength(2);
			expect(roles).toContain("editor");
			expect(roles).toContain("viewer");
		});

		test("returns cursor when limit is reached", async () => {
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

		test("returns no cursor when all roles fit within the limit", async () => {
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			const { roles, cursor } = await connector.getAllRoles(TEST_MODEL_ID, undefined, 10);
			expect(roles).toHaveLength(1);
			expect(cursor).toBeUndefined();
		});

		test("roles are returned in alphabetical order", async () => {
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "viewer");
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
			const { roles } = await connector.getAllRoles(TEST_MODEL_ID);
			expect(roles).toEqual(["admin", "editor", "viewer"]);
		});

		test("role is removed from index when last assignment is removed", async () => {
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			await connector.addRoleForSubject(TEST_MODEL_ID, "bob", "admin");
			await connector.removeRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			const { roles } = await connector.getAllRoles(TEST_MODEL_ID);
			expect(roles).toContain("admin");
			await connector.removeRoleForSubject(TEST_MODEL_ID, "bob", "admin");
			const { roles: roles2 } = await connector.getAllRoles(TEST_MODEL_ID);
			expect(roles2).not.toContain("admin");
		});

		test("role kept in index when still referenced by inheritance after assignment removed", async () => {
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
			await connector.addRoleInheritance(TEST_MODEL_ID, "admin", "editor");
			await connector.removeRoleForSubject(TEST_MODEL_ID, "alice", "editor");
			const { roles } = await connector.getAllRoles(TEST_MODEL_ID);
			expect(roles).toContain("editor");
		});

		test("role removed from index when all assignments and inheritance removed", async () => {
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
			await connector.addRoleInheritance(TEST_MODEL_ID, "admin", "editor");
			await connector.removeRoleForSubject(TEST_MODEL_ID, "alice", "editor");
			await connector.removeRoleInheritance(TEST_MODEL_ID, "admin", "editor");
			const { roles } = await connector.getAllRoles(TEST_MODEL_ID);
			expect(roles).not.toContain("editor");
		});

		test("removeAllRolesForSubject cleans up unreferenced role names", async () => {
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
			await connector.addRoleForSubject(TEST_MODEL_ID, "bob", "editor");
			await connector.removeAllRolesForSubject(TEST_MODEL_ID, "alice");
			const { roles } = await connector.getAllRoles(TEST_MODEL_ID);
			expect(roles).not.toContain("admin");
			expect(roles).toContain("editor");
		});
	});

	describe("hasRoles", () => {
		test("returns empty array for empty input", async () => {
			const result = await connector.hasRoles(TEST_MODEL_ID, []);
			expect(result).toEqual([]);
		});

		test("returns false for a role that does not exist", async () => {
			const result = await connector.hasRoles(TEST_MODEL_ID, ["unknown"]);
			expect(result).toEqual([false]);
		});

		test("returns true for a role added via addRoleForSubject", async () => {
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			const result = await connector.hasRoles(TEST_MODEL_ID, ["admin"]);
			expect(result).toEqual([true]);
		});

		test("returns true for a role added via addRoleInheritance", async () => {
			await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
			const result = await connector.hasRoles(TEST_MODEL_ID, ["editor", "viewer"]);
			expect(result).toEqual([true, true]);
		});

		test("returns results in input order with mixed existing and missing roles", async () => {
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			const result = await connector.hasRoles(TEST_MODEL_ID, ["admin", "missing", "admin"]);
			expect(result).toEqual([true, false, true]);
		});

		test("returns false after a role is removed and becomes unreferenced", async () => {
			await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "temp");
			await connector.removeRoleForSubject(TEST_MODEL_ID, "alice", "temp");
			const result = await connector.hasRoles(TEST_MODEL_ID, ["temp"]);
			expect(result).toEqual([false]);
		});
	});

	describe("removeRoleInheritance", () => {
		test("removes an inheritance relationship", async () => {
			await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
			await connector.removeRoleInheritance(TEST_MODEL_ID, "editor", "viewer");
			const parents = await connector.getParentRoles(TEST_MODEL_ID, "editor");
			expect(parents).toHaveLength(0);
		});

		test("only removes the targeted inheritance, leaving others intact", async () => {
			await connector.addRoleInheritance(TEST_MODEL_ID, "admin", "editor");
			await connector.addRoleInheritance(TEST_MODEL_ID, "admin", "viewer");
			await connector.removeRoleInheritance(TEST_MODEL_ID, "admin", "viewer");
			const parents = await connector.getParentRoles(TEST_MODEL_ID, "admin");
			expect(parents).toHaveLength(1);
			expect(parents[0]).toBe("editor");
		});

		test("removing a non-existent inheritance does not throw", async () => {
			await expect(
				connector.removeRoleInheritance(TEST_MODEL_ID, "editor", "viewer")
			).resolves.toBeUndefined();
		});
	});

	describe("multi-tenant isolation", () => {
		let tenantPolicyStorage: MemoryEntityStorageConnector<AuthorizationPolicy>;
		let tenantRoleStorage: MemoryEntityStorageConnector<AuthorizationRoleAssignment>;
		let tenantInheritanceStorage: MemoryEntityStorageConnector<AuthorizationRoleInheritance>;
		let tenantRoleNameStorage: MemoryEntityStorageConnector<AuthorizationRoleName>;
		let tenantConnector: EntityStorageAuthorizationConnector;

		beforeEach(async () => {
			tenantPolicyStorage = new MemoryEntityStorageConnector<AuthorizationPolicy>({
				entitySchema: nameof<AuthorizationPolicy>(),
				partitionContextIds: [ContextIdKeys.Tenant],
				config: { storageKey: "tenant-authorization-policy" }
			});
			await tenantPolicyStorage.teardown();
			EntityStorageConnectorFactory.register(
				"tenant-authorization-policy",
				() => tenantPolicyStorage
			);

			tenantRoleStorage = new MemoryEntityStorageConnector<AuthorizationRoleAssignment>({
				entitySchema: nameof<AuthorizationRoleAssignment>(),
				partitionContextIds: [ContextIdKeys.Tenant],
				config: { storageKey: "tenant-authorization-role-assignment" }
			});
			await tenantRoleStorage.teardown();
			EntityStorageConnectorFactory.register(
				"tenant-authorization-role-assignment",
				() => tenantRoleStorage
			);

			tenantInheritanceStorage = new MemoryEntityStorageConnector<AuthorizationRoleInheritance>({
				entitySchema: nameof<AuthorizationRoleInheritance>(),
				partitionContextIds: [ContextIdKeys.Tenant],
				config: { storageKey: "tenant-authorization-role-inheritance" }
			});
			await tenantInheritanceStorage.teardown();
			EntityStorageConnectorFactory.register(
				"tenant-authorization-role-inheritance",
				() => tenantInheritanceStorage
			);

			tenantRoleNameStorage = new MemoryEntityStorageConnector<AuthorizationRoleName>({
				entitySchema: nameof<AuthorizationRoleName>(),
				partitionContextIds: [ContextIdKeys.Tenant],
				config: { storageKey: "tenant-authorization-role-name" }
			});
			await tenantRoleNameStorage.teardown();
			EntityStorageConnectorFactory.register(
				"tenant-authorization-role-name",
				() => tenantRoleNameStorage
			);

			tenantConnector = new EntityStorageAuthorizationConnector({
				authorizationPolicyEntityStorageType: "tenant-authorization-policy",
				authorizationRoleAssignmentEntityStorageType: "tenant-authorization-role-assignment",
				authorizationRoleInheritanceEntityStorageType: "tenant-authorization-role-inheritance",
				authorizationRoleNameEntityStorageType: "tenant-authorization-role-name"
			});
		});

		afterEach(async () => {
			await tenantPolicyStorage.teardown();
			await tenantRoleStorage.teardown();
			await tenantInheritanceStorage.teardown();
			await tenantRoleNameStorage.teardown();
		});

		test("policies added under one tenant are not visible to another", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await tenantConnector.addPolicy(TEST_MODEL_ID, "alice", "/data", "read");
			});
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_B }, async () => {
				await tenantConnector.addPolicy(TEST_MODEL_ID, "alice", "/data", "write");
			});

			const tenantAPolicies = await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A },
				async () => {
					const { entities } = await tenantConnector.getAllPolicies(TEST_MODEL_ID);
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
					const { entities } = await tenantConnector.getAllPolicies(TEST_MODEL_ID);
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
				await tenantConnector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			});
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_B }, async () => {
				await tenantConnector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
			});

			const tenantARoles = await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A },
				async () => tenantConnector.getRolesForSubject(TEST_MODEL_ID, "alice")
			);
			expect(tenantARoles).toEqual(["admin"]);

			const tenantBRoles = await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_B },
				async () => tenantConnector.getRolesForSubject(TEST_MODEL_ID, "alice")
			);
			expect(tenantBRoles).toEqual(["editor"]);
		});

		test("check only evaluates policies within the current tenant", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await tenantConnector.addPolicy(TEST_MODEL_ID, "alice", "/data", "read");
			});

			const allowedInA = await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A },
				async () => tenantConnector.check(TEST_MODEL_ID, "alice", "/data", "read")
			);
			expect(allowedInA).toBe(true);

			const deniedInB = await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_B },
				async () => tenantConnector.check(TEST_MODEL_ID, "alice", "/data", "read")
			);
			expect(deniedInB).toBe(false);
		});

		test("the same subject can have different roles in different tenants", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await tenantConnector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
				await tenantConnector.addPolicy(TEST_MODEL_ID, "admin", "/admin", "write");
			});
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_B }, async () => {
				await tenantConnector.addRoleForSubject(TEST_MODEL_ID, "alice", "viewer");
				await tenantConnector.addPolicy(TEST_MODEL_ID, "viewer", "/admin", "write");
			});

			const canWriteInA = await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A },
				async () => tenantConnector.check(TEST_MODEL_ID, "alice", "/admin", "write")
			);
			expect(canWriteInA).toBe(true);

			const canWriteInB = await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_B },
				async () => tenantConnector.check(TEST_MODEL_ID, "alice", "/admin", "write")
			);
			expect(canWriteInB).toBe(true);
		});

		test("getAllRoles returns only roles for the current tenant", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A }, async () => {
				await tenantConnector.addRoleForSubject(TEST_MODEL_ID, "alice", "admin");
			});
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_ID_B }, async () => {
				await tenantConnector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
			});

			const tenantARoles = await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_A },
				async () => {
					const { roles } = await tenantConnector.getAllRoles(TEST_MODEL_ID);
					return roles;
				}
			);
			expect(tenantARoles).toEqual(["admin"]);

			const tenantBRoles = await ContextIdStore.run(
				{ [ContextIdKeys.Tenant]: TEST_TENANT_ID_B },
				async () => {
					const { roles } = await tenantConnector.getAllRoles(TEST_MODEL_ID);
					return roles;
				}
			);
			expect(tenantBRoles).toEqual(["editor"]);
		});
	});
});
