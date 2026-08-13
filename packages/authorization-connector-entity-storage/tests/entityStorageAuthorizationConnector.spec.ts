// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { MemoryEntityStorageConnector } from "@twin.org/entity-storage-connector-memory";
import { EntityStorageConnectorFactory } from "@twin.org/entity-storage-models";
import { nameof } from "@twin.org/nameof";
import type { AuthorizationPolicy } from "../src/entities/authorizationPolicy.js";
import type { AuthorizationRoleAssignment } from "../src/entities/authorizationRoleAssignment.js";
import type { AuthorizationRoleInheritance } from "../src/entities/authorizationRoleInheritance.js";
import { EntityStorageAuthorizationConnector } from "../src/entityStorageAuthorizationConnector.js";
import { initSchema } from "../src/schema.js";

describe("EntityStorageAuthorizationConnector", () => {
	let policyStorage: MemoryEntityStorageConnector<AuthorizationPolicy>;
	let roleStorage: MemoryEntityStorageConnector<AuthorizationRoleAssignment>;
	let inheritanceStorage: MemoryEntityStorageConnector<AuthorizationRoleInheritance>;
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
			config: { storageKey: "authorization-role" }
		});
		await roleStorage.teardown();
		EntityStorageConnectorFactory.register("authorization-role", () => roleStorage);

		inheritanceStorage = new MemoryEntityStorageConnector<AuthorizationRoleInheritance>({
			entitySchema: nameof<AuthorizationRoleInheritance>(),
			config: { storageKey: "authorization-role-inheritance" }
		});
		await inheritanceStorage.teardown();
		EntityStorageConnectorFactory.register(
			"authorization-role-inheritance",
			() => inheritanceStorage
		);

		connector = new EntityStorageAuthorizationConnector();
	});

	afterEach(async () => {
		await policyStorage.teardown();
		await roleStorage.teardown();
		await inheritanceStorage.teardown();
	});

	test("can create an instance", () => {
		expect(connector).toBeDefined();
		expect(connector.className()).toBe("EntityStorageAuthorizationConnector");
	});

	describe("addPolicy / getAllPolicies", () => {
		test("stores a policy and retrieves it", async () => {
			await connector.addPolicy({ subject: "alice", object: "document", action: "read" });
			const { entities } = await connector.getAllPolicies();
			expect(entities).toHaveLength(1);
			expect(entities[0]).toEqual({ subject: "alice", object: "document", action: "read" });
		});

		test("stores multiple distinct policies", async () => {
			await connector.addPolicy({ subject: "alice", object: "document", action: "read" });
			await connector.addPolicy({ subject: "alice", object: "document", action: "write" });
			await connector.addPolicy({ subject: "bob", object: "report", action: "read" });
			const { entities } = await connector.getAllPolicies();
			expect(entities).toHaveLength(3);
		});

		test("adding the same policy twice is idempotent", async () => {
			await connector.addPolicy({ subject: "alice", object: "document", action: "read" });
			await connector.addPolicy({ subject: "alice", object: "document", action: "read" });
			const { entities } = await connector.getAllPolicies();
			expect(entities).toHaveLength(1);
		});

		test("filters by subject when subject is provided", async () => {
			await connector.addPolicy({ subject: "alice", object: "document", action: "read" });
			await connector.addPolicy({ subject: "bob", object: "report", action: "read" });
			const { entities } = await connector.getAllPolicies("alice");
			expect(entities).toHaveLength(1);
			expect(entities[0].subject).toBe("alice");
		});

		test("returns cursor when limit is reached", async () => {
			await connector.addPolicy({ subject: "alice", object: "a", action: "read" });
			await connector.addPolicy({ subject: "alice", object: "b", action: "read" });
			await connector.addPolicy({ subject: "alice", object: "c", action: "read" });
			const page1 = await connector.getAllPolicies(undefined, undefined, 2);
			expect(page1.entities).toHaveLength(2);
			expect(page1.cursor).toBeDefined();
			const page2 = await connector.getAllPolicies(undefined, page1.cursor, 2);
			expect(page2.entities).toHaveLength(1);
			expect(page2.cursor).toBeUndefined();
		});

		test("cursor and subject filter can be combined", async () => {
			await connector.addPolicy({ subject: "alice", object: "a", action: "read" });
			await connector.addPolicy({ subject: "alice", object: "b", action: "read" });
			await connector.addPolicy({ subject: "alice", object: "c", action: "read" });
			await connector.addPolicy({ subject: "bob", object: "d", action: "read" });
			const page1 = await connector.getAllPolicies("alice", undefined, 2);
			expect(page1.entities).toHaveLength(2);
			expect(page1.entities.every(p => p.subject === "alice")).toBe(true);
			expect(page1.cursor).toBeDefined();
			const page2 = await connector.getAllPolicies("alice", page1.cursor, 2);
			expect(page2.entities).toHaveLength(1);
			expect(page2.entities[0].subject).toBe("alice");
			expect(page2.cursor).toBeUndefined();
		});

		test("returns no cursor when all results fit within the limit", async () => {
			await connector.addPolicy({ subject: "alice", object: "document", action: "read" });
			const { entities, cursor } = await connector.getAllPolicies(undefined, undefined, 10);
			expect(entities).toHaveLength(1);
			expect(cursor).toBeUndefined();
		});

		test("throws when subject is empty", async () => {
			await expect(
				connector.addPolicy({ subject: "", object: "document", action: "read" })
			).rejects.toThrow();
		});

		test("throws when object is empty", async () => {
			await expect(
				connector.addPolicy({ subject: "alice", object: "", action: "read" })
			).rejects.toThrow();
		});

		test("throws when action is empty", async () => {
			await expect(
				connector.addPolicy({ subject: "alice", object: "document", action: "" })
			).rejects.toThrow();
		});
	});

	describe("removePolicy", () => {
		test("removes an existing policy", async () => {
			await connector.addPolicy({ subject: "alice", object: "document", action: "read" });
			await connector.removePolicy({ subject: "alice", object: "document", action: "read" });
			const { entities } = await connector.getAllPolicies();
			expect(entities).toHaveLength(0);
		});

		test("only removes the targeted policy", async () => {
			await connector.addPolicy({ subject: "alice", object: "document", action: "read" });
			await connector.addPolicy({ subject: "alice", object: "document", action: "write" });
			await connector.removePolicy({ subject: "alice", object: "document", action: "read" });
			const { entities } = await connector.getAllPolicies();
			expect(entities).toHaveLength(1);
			expect(entities[0].action).toBe("write");
		});

		test("removing a non-existent policy does not throw", async () => {
			await expect(
				connector.removePolicy({ subject: "alice", object: "document", action: "read" })
			).resolves.toBeUndefined();
		});
	});

	describe("getPoliciesForSubject", () => {
		test("returns only policies for the given subject", async () => {
			await connector.addPolicy({ subject: "alice", object: "document", action: "read" });
			await connector.addPolicy({ subject: "alice", object: "report", action: "write" });
			await connector.addPolicy({ subject: "bob", object: "document", action: "read" });

			const alicePolicies = await connector.getPoliciesForSubject("alice");
			expect(alicePolicies).toHaveLength(2);
			expect(alicePolicies.every(p => p.subject === "alice")).toBe(true);
		});

		test("returns empty array when subject has no policies", async () => {
			const policies = await connector.getPoliciesForSubject("nobody");
			expect(policies).toHaveLength(0);
		});

		test("throws when subject is empty", async () => {
			await expect(connector.getPoliciesForSubject("")).rejects.toThrow();
		});
	});

	describe("check", () => {
		test("returns true when a direct policy matches", async () => {
			await connector.addPolicy({ subject: "alice", object: "document", action: "read" });
			await expect(connector.check("alice", "document", "read")).resolves.toBe(true);
		});

		test("returns false when no policy matches the action", async () => {
			await connector.addPolicy({ subject: "alice", object: "document", action: "read" });
			await expect(connector.check("alice", "document", "write")).resolves.toBe(false);
		});

		test("returns false when no policy matches the object", async () => {
			await connector.addPolicy({ subject: "alice", object: "document", action: "read" });
			await expect(connector.check("alice", "report", "read")).resolves.toBe(false);
		});

		test("returns false when subject has no policies", async () => {
			await expect(connector.check("nobody", "document", "read")).resolves.toBe(false);
		});

		test("returns true when subject has a role with a matching policy", async () => {
			await connector.addPolicy({ subject: "admin", object: "report", action: "delete" });
			await connector.addRoleForSubject("alice", "admin");
			await expect(connector.check("alice", "report", "delete")).resolves.toBe(true);
		});

		test("returns false when role exists but has no matching policy", async () => {
			await connector.addPolicy({ subject: "admin", object: "report", action: "delete" });
			await connector.addRoleForSubject("alice", "editor");
			await expect(connector.check("alice", "report", "delete")).resolves.toBe(false);
		});

		test("returns true via single-level role inheritance", async () => {
			await connector.addPolicy({ subject: "viewer", object: "document", action: "read" });
			await connector.addRoleInheritance("editor", "viewer");
			await connector.addRoleForSubject("alice", "editor");
			await expect(connector.check("alice", "document", "read")).resolves.toBe(true);
		});

		test("returns true via multi-level role inheritance chain", async () => {
			await connector.addPolicy({ subject: "viewer", object: "document", action: "read" });
			await connector.addRoleInheritance("editor", "viewer");
			await connector.addRoleInheritance("admin", "editor");
			await connector.addRoleForSubject("alice", "admin");
			await expect(connector.check("alice", "document", "read")).resolves.toBe(true);
		});

		test("returns false when inherited role has no matching policy", async () => {
			await connector.addPolicy({ subject: "viewer", object: "document", action: "read" });
			await connector.addRoleInheritance("editor", "viewer");
			await connector.addRoleForSubject("alice", "editor");
			await expect(connector.check("alice", "document", "write")).resolves.toBe(false);
		});

		test("handles role cycles without looping forever", async () => {
			await connector.addRoleInheritance("a", "b");
			await connector.addRoleInheritance("b", "a");
			await connector.addRoleForSubject("alice", "a");
			await expect(connector.check("alice", "document", "read")).resolves.toBe(false);
		});

		test("throws when subject is empty", async () => {
			await expect(connector.check("", "document", "read")).rejects.toThrow();
		});

		test("throws when object is empty", async () => {
			await expect(connector.check("alice", "", "read")).rejects.toThrow();
		});

		test("throws when action is empty", async () => {
			await expect(connector.check("alice", "document", "")).rejects.toThrow();
		});
	});

	describe("addRoleForSubject / hasRoleForSubject", () => {
		test("assigns a role and confirms it exists", async () => {
			await connector.addRoleForSubject("alice", "admin");
			await expect(connector.hasRoleForSubject("alice", "admin")).resolves.toBe(true);
		});

		test("returns false when role is not assigned to subject", async () => {
			await expect(connector.hasRoleForSubject("alice", "admin")).resolves.toBe(false);
		});

		test("assigning the same role twice is idempotent", async () => {
			await connector.addRoleForSubject("alice", "admin");
			await connector.addRoleForSubject("alice", "admin");
			const roles = await connector.getRolesForSubject("alice");
			expect(roles).toHaveLength(1);
		});

		test("throws when subject is empty", async () => {
			await expect(connector.addRoleForSubject("", "admin")).rejects.toThrow();
		});

		test("throws when role is empty", async () => {
			await expect(connector.addRoleForSubject("alice", "")).rejects.toThrow();
		});
	});

	describe("removeRoleForSubject", () => {
		test("removes an assigned role", async () => {
			await connector.addRoleForSubject("alice", "admin");
			await connector.removeRoleForSubject("alice", "admin");
			await expect(connector.hasRoleForSubject("alice", "admin")).resolves.toBe(false);
		});

		test("only removes the targeted role, leaving others intact", async () => {
			await connector.addRoleForSubject("alice", "admin");
			await connector.addRoleForSubject("alice", "editor");
			await connector.removeRoleForSubject("alice", "editor");
			await expect(connector.hasRoleForSubject("alice", "admin")).resolves.toBe(true);
			await expect(connector.hasRoleForSubject("alice", "editor")).resolves.toBe(false);
		});

		test("removing a non-existent role does not throw", async () => {
			await expect(connector.removeRoleForSubject("alice", "admin")).resolves.toBeUndefined();
		});
	});

	describe("removeAllRolesForSubject", () => {
		test("removes all roles from a subject", async () => {
			await connector.addRoleForSubject("alice", "admin");
			await connector.addRoleForSubject("alice", "editor");
			await connector.removeAllRolesForSubject("alice");
			const roles = await connector.getRolesForSubject("alice");
			expect(roles).toHaveLength(0);
		});

		test("does not affect roles of other subjects", async () => {
			await connector.addRoleForSubject("alice", "admin");
			await connector.addRoleForSubject("bob", "editor");
			await connector.removeAllRolesForSubject("alice");
			const bobRoles = await connector.getRolesForSubject("bob");
			expect(bobRoles).toHaveLength(1);
			expect(bobRoles[0]).toBe("editor");
		});

		test("succeeds when subject has no roles", async () => {
			await expect(connector.removeAllRolesForSubject("nobody")).resolves.toBeUndefined();
		});
	});

	describe("getRolesForSubject", () => {
		test("returns all roles assigned to a subject", async () => {
			await connector.addRoleForSubject("alice", "admin");
			await connector.addRoleForSubject("alice", "editor");
			const roles = await connector.getRolesForSubject("alice");
			expect(roles).toHaveLength(2);
			expect(roles).toContain("admin");
			expect(roles).toContain("editor");
		});

		test("returns empty array when subject has no roles", async () => {
			const roles = await connector.getRolesForSubject("nobody");
			expect(roles).toHaveLength(0);
		});

		test("throws when subject is empty", async () => {
			await expect(connector.getRolesForSubject("")).rejects.toThrow();
		});
	});

	describe("getSubjectsForRole", () => {
		test("returns all subjects with a given role", async () => {
			await connector.addRoleForSubject("alice", "admin");
			await connector.addRoleForSubject("bob", "admin");
			await connector.addRoleForSubject("carol", "editor");
			const subjects = await connector.getSubjectsForRole("admin");
			expect(subjects).toHaveLength(2);
			expect(subjects).toContain("alice");
			expect(subjects).toContain("bob");
		});

		test("returns empty array when no subjects have the role", async () => {
			const subjects = await connector.getSubjectsForRole("unknown-role");
			expect(subjects).toHaveLength(0);
		});

		test("throws when role is empty", async () => {
			await expect(connector.getSubjectsForRole("")).rejects.toThrow();
		});
	});

	describe("addRoleInheritance / getParentRoles / getChildRoles", () => {
		test("defines inheritance and retrieves parent roles", async () => {
			await connector.addRoleInheritance("editor", "viewer");
			const parents = await connector.getParentRoles("editor");
			expect(parents).toHaveLength(1);
			expect(parents[0]).toBe("viewer");
		});

		test("defines inheritance and retrieves child roles", async () => {
			await connector.addRoleInheritance("editor", "viewer");
			const children = await connector.getChildRoles("viewer");
			expect(children).toHaveLength(1);
			expect(children[0]).toBe("editor");
		});

		test("a role can have multiple parents", async () => {
			await connector.addRoleInheritance("superuser", "admin");
			await connector.addRoleInheritance("superuser", "editor");
			const parents = await connector.getParentRoles("superuser");
			expect(parents).toHaveLength(2);
			expect(parents).toContain("admin");
			expect(parents).toContain("editor");
		});

		test("a role can have multiple children", async () => {
			await connector.addRoleInheritance("editor", "viewer");
			await connector.addRoleInheritance("admin", "viewer");
			const children = await connector.getChildRoles("viewer");
			expect(children).toHaveLength(2);
			expect(children).toContain("editor");
			expect(children).toContain("admin");
		});

		test("adding the same inheritance twice is idempotent", async () => {
			await connector.addRoleInheritance("editor", "viewer");
			await connector.addRoleInheritance("editor", "viewer");
			const parents = await connector.getParentRoles("editor");
			expect(parents).toHaveLength(1);
		});

		test("returns empty array when role has no parents", async () => {
			const parents = await connector.getParentRoles("viewer");
			expect(parents).toHaveLength(0);
		});

		test("returns empty array when role has no children", async () => {
			const children = await connector.getChildRoles("admin");
			expect(children).toHaveLength(0);
		});

		test("throws when role is empty for addRoleInheritance", async () => {
			await expect(connector.addRoleInheritance("", "viewer")).rejects.toThrow();
		});

		test("throws when parentRole is empty for addRoleInheritance", async () => {
			await expect(connector.addRoleInheritance("editor", "")).rejects.toThrow();
		});

		test("throws when role is empty for getParentRoles", async () => {
			await expect(connector.getParentRoles("")).rejects.toThrow();
		});

		test("throws when role is empty for getChildRoles", async () => {
			await expect(connector.getChildRoles("")).rejects.toThrow();
		});
	});

	describe("getAllRoles", () => {
		test("returns empty when no roles are assigned", async () => {
			const { roles } = await connector.getAllRoles();
			expect(roles).toHaveLength(0);
		});

		test("returns distinct roles from role assignments", async () => {
			await connector.addRoleForSubject("alice", "admin");
			await connector.addRoleForSubject("bob", "admin");
			await connector.addRoleForSubject("carol", "editor");
			const { roles } = await connector.getAllRoles();
			expect(roles).toHaveLength(2);
			expect(roles).toContain("admin");
			expect(roles).toContain("editor");
		});

		test("returns distinct roles from role inheritance", async () => {
			await connector.addRoleForSubject("alice", "editor");
			await connector.addRoleInheritance("editor", "viewer");
			const { roles } = await connector.getAllRoles();
			expect(roles).toHaveLength(2);
			expect(roles).toContain("editor");
			expect(roles).toContain("viewer");
		});

		test("returns cursor when limit is reached", async () => {
			await connector.addRoleForSubject("alice", "admin");
			await connector.addRoleForSubject("alice", "editor");
			await connector.addRoleForSubject("alice", "viewer");
			const page1 = await connector.getAllRoles(undefined, 2);
			expect(page1.roles).toHaveLength(2);
			expect(page1.cursor).toBeDefined();
			const page2 = await connector.getAllRoles(page1.cursor, 2);
			expect(page2.roles).toHaveLength(1);
			expect(page2.cursor).toBeUndefined();
		});

		test("returns no cursor when all roles fit within the limit", async () => {
			await connector.addRoleForSubject("alice", "admin");
			const { roles, cursor } = await connector.getAllRoles(undefined, 10);
			expect(roles).toHaveLength(1);
			expect(cursor).toBeUndefined();
		});

		test("roles are returned in alphabetical order", async () => {
			await connector.addRoleForSubject("alice", "viewer");
			await connector.addRoleForSubject("alice", "admin");
			await connector.addRoleForSubject("alice", "editor");
			const { roles } = await connector.getAllRoles();
			expect(roles).toEqual(["admin", "editor", "viewer"]);
		});
	});

	describe("removeRoleInheritance", () => {
		test("removes an inheritance relationship", async () => {
			await connector.addRoleInheritance("editor", "viewer");
			await connector.removeRoleInheritance("editor", "viewer");
			const parents = await connector.getParentRoles("editor");
			expect(parents).toHaveLength(0);
		});

		test("only removes the targeted inheritance, leaving others intact", async () => {
			await connector.addRoleInheritance("admin", "editor");
			await connector.addRoleInheritance("admin", "viewer");
			await connector.removeRoleInheritance("admin", "viewer");
			const parents = await connector.getParentRoles("admin");
			expect(parents).toHaveLength(1);
			expect(parents[0]).toBe("editor");
		});

		test("removing a non-existent inheritance does not throw", async () => {
			await expect(connector.removeRoleInheritance("editor", "viewer")).resolves.toBeUndefined();
		});
	});
});
