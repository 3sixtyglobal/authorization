// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { ContextIdKeys, ContextIdStore } from "@3sixty/context";
import { Converter, GeneralError, GuardError } from "@3sixty/core";
import { FetchHelper, HttpMethod } from "@3sixty/web";
import {
	TEST_CASBIN_CLIENT_ID,
	TEST_CASBIN_CLIENT_SECRET,
	TEST_CASBIN_ENDPOINT
} from "./setupTestEnv.js";
import { CasbinAuthorizationConnector } from "../src/casbinAuthorizationConnector.js";

const TEST_TENANT_A = "test-tenant-a";
const TEST_MODEL_ID = "test-model";
const UNPROVISIONED_MODEL_ID = "never-provisioned-model";

describe("CasbinAuthorizationConnector (casbin-specific)", () => {
	let connector: CasbinAuthorizationConnector;

	async function cleanup(): Promise<void> {
		await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_A }, async () => {
			let { entities: policies } = await connector.getAllPolicies(TEST_MODEL_ID);
			while (policies.length > 0) {
				for (const policy of policies) {
					await connector.removePolicy(TEST_MODEL_ID, policy.subject, policy.object, policy.action);
				}
				({ entities: policies } = await connector.getAllPolicies(TEST_MODEL_ID));
			}
			for (const subject of ["alice", "editor", "a"]) {
				await connector.removeAllRolesForSubject(TEST_MODEL_ID, subject);
			}
			for (const role of ["editor", "viewer", "alice", "a"]) {
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
				await expect(badConnector.getAllPolicies(TEST_MODEL_ID)).rejects.toMatchObject({
					name: GeneralError.CLASS_NAME
				});
			});
		});

		test("getAllRoles throws on server failure rather than returning empty", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_A }, async () => {
				await expect(badConnector.getAllRoles(TEST_MODEL_ID)).rejects.toMatchObject({
					name: GeneralError.CLASS_NAME
				});
			});
		});

		test("hasRoles throws on server failure rather than returning all-false", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_A }, async () => {
				await expect(badConnector.hasRoles(TEST_MODEL_ID, ["admin"])).rejects.toMatchObject({
					name: GeneralError.CLASS_NAME
				});
			});
		});
	});

	describe("unprovisioned models", () => {
		test("reads on an unknown model return empty results without creating the enforcer", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_A }, async () => {
				const modelId = UNPROVISIONED_MODEL_ID;
				await expect(connector.check(modelId, "alice", "document", "read")).resolves.toBe(false);
				await expect(connector.getAllPolicies(modelId)).resolves.toEqual({ entities: [] });
				await expect(connector.getAllRoles(modelId)).resolves.toEqual({ roles: [] });
				await expect(connector.hasRoles(modelId, ["admin"])).resolves.toEqual([false]);
				await expect(connector.getRolesForSubject(modelId, "alice")).resolves.toEqual([]);
				await expect(connector.getParentRoles(modelId, "admin")).resolves.toEqual([]);
				await expect(
					connector.removePolicy(modelId, "alice", "document", "read")
				).resolves.toBeUndefined();
				await expect(connector.removeAllRolesForSubject(modelId, "alice")).resolves.toBeUndefined();

				const credentials = Converter.bytesToBase64(
					Converter.utf8ToBytes(`${TEST_CASBIN_CLIENT_ID}:${TEST_CASBIN_CLIENT_SECRET}`)
				);
				const response = await FetchHelper.fetchJson<never, { status: string; data: unknown }>(
					"test",
					`${TEST_CASBIN_ENDPOINT}/api/get-enforcer?id=${encodeURIComponent(`${TEST_TENANT_A}/${modelId}`)}`,
					HttpMethod.GET,
					undefined,
					{ headers: { Authorization: `Basic ${credentials}` } }
				);
				expect(response.status).toBe("ok");
				expect(response.data).toBeNull();
			});
		});
	});

	describe("casdoor model", () => {
		test("provisions enforcers with the tenant's own model", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_A }, async () => {
				await connector.addRoleForSubject(TEST_MODEL_ID, "alice", "editor");
				await connector.addRoleInheritance(TEST_MODEL_ID, "editor", "viewer");

				const headers = {
					Authorization: `Basic ${Converter.bytesToBase64(
						Converter.utf8ToBytes(`${TEST_CASBIN_CLIENT_ID}:${TEST_CASBIN_CLIENT_SECRET}`)
					)}`
				};
				const enforcer = await FetchHelper.fetchJson<never, { data: { model: string } }>(
					"test",
					`${TEST_CASBIN_ENDPOINT}/api/get-enforcer?id=${encodeURIComponent(`${TEST_TENANT_A}/${TEST_MODEL_ID}`)}`,
					HttpMethod.GET,
					undefined,
					{ headers }
				);
				expect(enforcer.data.model).toBe(`${TEST_TENANT_A}/authorization`);

				const model = await FetchHelper.fetchJson<never, { data: { modelText: string } }>(
					"test",
					`${TEST_CASBIN_ENDPOINT}/api/get-model?id=${encodeURIComponent(`${TEST_TENANT_A}/authorization`)}`,
					HttpMethod.GET,
					undefined,
					{ headers }
				);
				expect(model.data.modelText).toContain("g = _, _, _");

				const rules = await FetchHelper.fetchJson<
					never,
					{ data: { Ptype: string; V0: string; V1: string; V2: string }[] }
				>(
					"test",
					`${TEST_CASBIN_ENDPOINT}/api/get-policies?id=${encodeURIComponent(`${TEST_TENANT_A}/${TEST_MODEL_ID}`)}`,
					HttpMethod.GET,
					undefined,
					{ headers }
				);
				expect(rules.data).toEqual(
					expect.arrayContaining([
						expect.objectContaining({ Ptype: "g", V0: "alice", V1: "editor", V2: "assigned" }),
						expect.objectContaining({ Ptype: "g", V0: "editor", V1: "viewer", V2: "inherits" })
					])
				);
			});
		});
	});

	describe("validation", () => {
		test("rejects a model id containing a slash", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_A }, async () => {
				await expect(connector.addPolicy("a/b", "alice", "document", "read")).rejects.toMatchObject(
					{
						name: GeneralError.CLASS_NAME,
						message: "casbinAuthorizationConnector.containsPathSeparator"
					}
				);
				await expect(connector.getAllRoles("a/b")).rejects.toMatchObject({
					name: GeneralError.CLASS_NAME
				});
			});
		});

		test("rejects a tenant id containing a slash", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: "tenant/x" }, async () => {
				await expect(
					connector.check(TEST_MODEL_ID, "alice", "document", "read")
				).rejects.toMatchObject({ name: GeneralError.CLASS_NAME });
			});
		});

		test.each(["abc", "-1", "1.5", ""])("rejects invalid cursor %j", async cursor => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_A }, async () => {
				await expect(
					connector.getAllPolicies(TEST_MODEL_ID, undefined, cursor, 10)
				).rejects.toMatchObject({ name: GuardError.CLASS_NAME });
				await expect(connector.getAllRoles(TEST_MODEL_ID, cursor, 10)).rejects.toMatchObject({
					name: GuardError.CLASS_NAME
				});
			});
		});

		test.each([0, -1, 1.5])("rejects invalid limit %j", async limit => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_A }, async () => {
				await expect(
					connector.getPoliciesForSubject(TEST_MODEL_ID, "alice", undefined, limit)
				).rejects.toMatchObject({ name: GuardError.CLASS_NAME });
				await expect(connector.getAllRoles(TEST_MODEL_ID, undefined, limit)).rejects.toMatchObject({
					name: GuardError.CLASS_NAME
				});
			});
		});

		test("applies a default page size and sorts deterministically when no limit is given", async () => {
			await ContextIdStore.run({ [ContextIdKeys.Tenant]: TEST_TENANT_A }, async () => {
				for (let i = 44; i >= 0; i--) {
					await connector.addPolicy(
						TEST_MODEL_ID,
						"alice",
						`doc-${String(i).padStart(2, "0")}`,
						"read"
					);
				}
				const page1 = await connector.getAllPolicies(TEST_MODEL_ID);
				expect(page1.entities).toHaveLength(40);
				expect(page1.entities[0].object).toBe("doc-00");
				expect(page1.cursor).toBe("40");
				const page2 = await connector.getAllPolicies(TEST_MODEL_ID, undefined, page1.cursor);
				expect(page2.entities.map(p => p.object)).toEqual([
					"doc-40",
					"doc-41",
					"doc-42",
					"doc-43",
					"doc-44"
				]);
				expect(page2.cursor).toBeUndefined();
			});
		});
	});
});
