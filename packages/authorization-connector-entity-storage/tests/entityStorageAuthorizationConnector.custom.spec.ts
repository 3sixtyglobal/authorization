// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IEntityStorageConnector } from "@3sixty/entity-storage-models";
import { createTestStorages, teardownTestStorages, TEST_STORAGE_BACKENDS } from "./testStorage.js";
import { EntityStorageAuthorizationConnector } from "../src/entityStorageAuthorizationConnector.js";
import { initSchema } from "../src/schema.js";

const TEST_MODEL_ID = "test-model";

describe.each(TEST_STORAGE_BACKENDS)(
	"EntityStorageAuthorizationConnector (entity-storage-specific, $name)",
	backend => {
		let storages: IEntityStorageConnector[];
		let connector: EntityStorageAuthorizationConnector;

		beforeEach(async () => {
			initSchema();
			storages = await createTestStorages(backend);
			connector = new EntityStorageAuthorizationConnector();
		});

		afterEach(async () => {
			await teardownTestStorages(storages);
		});

		describe("compound id length", () => {
			const long = "x".repeat(200);

			test("addPolicy rejects an id longer than the primary key", async () => {
				await expect(connector.addPolicy(TEST_MODEL_ID, long, long, "read")).rejects.toMatchObject({
					message: "entityStorageAuthorizationConnector.idTooLong"
				});
			});

			test("addRoleForSubject rejects an id longer than the primary key", async () => {
				await expect(
					connector.addRoleForSubject(TEST_MODEL_ID, long, "x".repeat(100))
				).rejects.toMatchObject({ message: "entityStorageAuthorizationConnector.idTooLong" });
				expect(await connector.getAllRoles(TEST_MODEL_ID)).toEqual({ roles: [] });
			});

			test("addRoleInheritance rejects an id longer than the primary key", async () => {
				await expect(
					connector.addRoleInheritance(TEST_MODEL_ID, "x".repeat(128), "y".repeat(128))
				).rejects.toMatchObject({ message: "entityStorageAuthorizationConnector.idTooLong" });
			});

			test("accepts an id at the maximum length", async () => {
				const subject = "s".repeat(255 - TEST_MODEL_ID.length - "|document|read".length - 1);
				await connector.addPolicy(TEST_MODEL_ID, subject, "document", "read");
				expect(await connector.check(TEST_MODEL_ID, subject, "document", "read")).toBe(true);
			});
		});
	}
);
