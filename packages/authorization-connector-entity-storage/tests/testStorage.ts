// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { RandomHelper } from "@3sixty/core";
import { MemoryEntityStorageConnector } from "@3sixty/entity-storage-connector-memory";
import { PostgreSqlEntityStorageConnector } from "@3sixty/entity-storage-connector-postgresql";
import {
	EntityStorageConnectorFactory,
	type IEntityStorageConnector
} from "@3sixty/entity-storage-models";
import { nameof } from "@3sixty/nameof";
import { TEST_POSTGRESQL_CONFIG } from "./setupTestEnv.js";
import type { AuthorizationPolicy } from "../src/entities/authorizationPolicy.js";
import type { AuthorizationRoleAssignment } from "../src/entities/authorizationRoleAssignment.js";
import type { AuthorizationRoleInheritance } from "../src/entities/authorizationRoleInheritance.js";
import type { AuthorizationRoleName } from "../src/entities/authorizationRoleName.js";

/**
 * The entity storage backends the connector tests run against.
 */
export const TEST_STORAGE_BACKENDS: { name: "memory" | "postgresql" }[] = [
	{ name: "memory" },
	{ name: "postgresql" }
];

/**
 * The storages used by the connector with their registered types and short table suffixes.
 */
const STORAGES: { type: string; tableSuffix: string; entitySchema: string }[] = [
	{
		type: "authorization-policy",
		tableSuffix: "p",
		entitySchema: nameof<AuthorizationPolicy>()
	},
	{
		type: "authorization-role-assignment",
		tableSuffix: "ra",
		entitySchema: nameof<AuthorizationRoleAssignment>()
	},
	{
		type: "authorization-role-inheritance",
		tableSuffix: "ri",
		entitySchema: nameof<AuthorizationRoleInheritance>()
	},
	{
		type: "authorization-role-name",
		tableSuffix: "rn",
		entitySchema: nameof<AuthorizationRoleName>()
	}
];

/**
 * Create, bootstrap and register empty storages for the connector on the given backend.
 * @param backend The backend to create the storages on.
 * @param typePrefix The prefix for the registered storage types.
 * @param partitionContextIds The optional context ids to partition the storages by.
 * @returns The created storages.
 */
export async function createTestStorages(
	backend: (typeof TEST_STORAGE_BACKENDS)[number],
	typePrefix: string = "",
	partitionContextIds?: string[]
): Promise<IEntityStorageConnector[]> {
	const storages: IEntityStorageConnector[] = [];
	const tableId = RandomHelper.generateUuidV7("compact");

	for (const storage of STORAGES) {
		let connector: IEntityStorageConnector;
		if (backend.name === "postgresql") {
			connector = new PostgreSqlEntityStorageConnector({
				entitySchema: storage.entitySchema,
				partitionContextIds,
				config: {
					...TEST_POSTGRESQL_CONFIG,
					tableName: `${TEST_POSTGRESQL_CONFIG.tableName}_${storage.tableSuffix}_${tableId}`
				}
			});
			await connector.bootstrap?.();
		} else {
			connector = new MemoryEntityStorageConnector({
				entitySchema: storage.entitySchema,
				partitionContextIds,
				config: { storageKey: `${typePrefix}${storage.type}` }
			});
			await connector.teardown?.();
		}
		EntityStorageConnectorFactory.register(`${typePrefix}${storage.type}`, () => connector);
		storages.push(connector);
	}

	return storages;
}

/**
 * Remove the data and release the resources of the storages.
 * @param storages The storages to tear down.
 */
export async function teardownTestStorages(storages: IEntityStorageConnector[]): Promise<void> {
	for (const storage of storages) {
		await storage.teardown?.();
		await storage.stop?.();
	}
}
