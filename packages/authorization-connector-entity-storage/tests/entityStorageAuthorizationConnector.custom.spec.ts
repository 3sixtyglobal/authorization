// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { MemoryEntityStorageConnector } from "@3sixty/entity-storage-connector-memory";
import { EntityStorageConnectorFactory } from "@3sixty/entity-storage-models";
import { nameof } from "@3sixty/nameof";
import type { AuthorizationPolicy } from "../src/entities/authorizationPolicy.js";
import type { AuthorizationRoleAssignment } from "../src/entities/authorizationRoleAssignment.js";
import type { AuthorizationRoleInheritance } from "../src/entities/authorizationRoleInheritance.js";
import type { AuthorizationRoleName } from "../src/entities/authorizationRoleName.js";
import { EntityStorageAuthorizationConnector } from "../src/entityStorageAuthorizationConnector.js";
import { initSchema } from "../src/schema.js";

const TEST_MODEL_ID = "test-model";

describe("EntityStorageAuthorizationConnector (entity-storage-specific)", () => {
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

	describe("addPolicy separator collision", () => {
		test("a|b subject and b|c object do not collide with a subject and a b|c compound object", async () => {
			await connector.addPolicy(TEST_MODEL_ID, "alice", "document", "read");
			await expect(connector.addPolicy(TEST_MODEL_ID, "a|b", "c", "execute")).rejects.toThrow();
			await expect(connector.check(TEST_MODEL_ID, "a", "b|c", "execute")).rejects.toThrow();
		});
	});
});
