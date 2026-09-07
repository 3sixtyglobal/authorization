// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { ContextIdKeys, ContextIdStore } from "@twin.org/context";
import {
	TEST_CASBIN_CLIENT_ID,
	TEST_CASBIN_CLIENT_SECRET,
	TEST_CASBIN_ENDPOINT
} from "./setupTestEnv.js";
import { CasbinAuthorizationConnector } from "../src/casbinAuthorizationConnector.js";

const TEST_TENANT_A = "test-tenant-a";
const TEST_MODEL_ID = "test-model";

describe("CasbinAuthorizationConnector (casbin-specific)", () => {
	let connector: CasbinAuthorizationConnector;

	async function cleanup(): Promise<void> {
		await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_A }, async () => {
			const { entities: policies } = await connector.getAllPolicies(TEST_MODEL_ID);
			for (const policy of policies) {
				await connector.removePolicy(TEST_MODEL_ID, policy.subject, policy.object, policy.action);
			}
			for (const subject of ["alice"]) {
				await connector.removeAllRolesForSubject(TEST_MODEL_ID, subject);
			}
			for (const role of ["editor", "viewer"]) {
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

	describe("error propagation", () => {
		let badConnector: CasbinAuthorizationConnector;

		beforeEach(() => {
			badConnector = new CasbinAuthorizationConnector({
				config: {
					endpoint: "http://localhost:0",
					clientId: TEST_CASBIN_CLIENT_ID,
					clientSecret: TEST_CASBIN_CLIENT_SECRET
				}
			});
		});

		test("getAllPolicies throws on server failure rather than returning empty", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_A }, async () => {
				await expect(badConnector.getAllPolicies(TEST_MODEL_ID)).rejects.toThrow();
			});
		});

		test("getAllRoles throws on server failure rather than returning empty", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_A }, async () => {
				await expect(badConnector.getAllRoles(TEST_MODEL_ID)).rejects.toThrow();
			});
		});

		test("hasRoles throws on server failure rather than returning all-false", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_A }, async () => {
				await expect(badConnector.hasRoles(TEST_MODEL_ID, ["admin"])).rejects.toThrow();
			});
		});
	});
});
