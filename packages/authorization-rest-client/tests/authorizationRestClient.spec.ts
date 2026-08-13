// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IAuthorizationPolicy } from "@twin.org/authorization-models";
import { GuardError } from "@twin.org/core";
import { HttpMethod } from "@twin.org/web";
import { AuthorizationRestClient } from "../src/authorizationRestClient.js";
import {
	jsonResponse,
	noContentResponse,
	setupFetchMock,
	teardownFetchMock
} from "./helpers/restClientTestHelpers.js";

// OpenAPI spec: ../../authorization-service/docs/open-api/spec.json
const ENDPOINT = "http://localhost:8080";
const PREFIX = "authorization";

const SUBJECT = "user1";
const OBJECT = "/data";
const ACTION = "read";
const ROLE = "admin";
const PARENT_ROLE = "viewer";

const TEST_POLICY: IAuthorizationPolicy = { subject: SUBJECT, object: OBJECT, action: ACTION };

const fetchMock = vi.fn();

describe("AuthorizationRestClient", () => {
	let client: AuthorizationRestClient;

	beforeEach(() => {
		setupFetchMock(fetchMock);
		client = new AuthorizationRestClient({ endpoint: ENDPOINT });
	});

	afterEach(() => {
		teardownFetchMock(fetchMock);
	});

	test("class name is set", () => {
		expect(client.className()).toBe("AuthorizationRestClient");
	});

	describe("check", () => {
		test("throws when subject is empty", async () => {
			await expect(client.check("", OBJECT, ACTION)).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("throws when object is empty", async () => {
			await expect(client.check(SUBJECT, "", ACTION)).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("throws when action is empty", async () => {
			await expect(client.check(SUBJECT, OBJECT, "")).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("sends POST to /{prefix}/check", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ allowed: true }));

			await client.check(SUBJECT, OBJECT, ACTION);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/check`);
			expect(options.method).toBe(HttpMethod.POST);
		});

		test("sends subject, object and action in the request body", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ allowed: true }));

			await client.check(SUBJECT, OBJECT, ACTION);

			const [, options] = fetchMock.mock.calls[0];
			const body = JSON.parse(options.body);
			expect(body.subject).toBe(SUBJECT);
			expect(body.object).toBe(OBJECT);
			expect(body.action).toBe(ACTION);
		});

		test("returns true when allowed", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ allowed: true }));

			const result = await client.check(SUBJECT, OBJECT, ACTION);

			expect(result).toBe(true);
		});

		test("returns false when not allowed", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ allowed: false }));

			const result = await client.check(SUBJECT, OBJECT, ACTION);

			expect(result).toBe(false);
		});
	});

	describe("addPolicy", () => {
		test("throws when policy is undefined", async () => {
			await expect(client.addPolicy(undefined as never)).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.objectUndefined"
			});
		});

		test("sends POST to /{prefix}/policy", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			await client.addPolicy(TEST_POLICY);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/policy`);
			expect(options.method).toBe(HttpMethod.POST);
		});

		test("sends policy fields in the request body", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			await client.addPolicy(TEST_POLICY);

			const [, options] = fetchMock.mock.calls[0];
			const body = JSON.parse(options.body);
			expect(body.subject).toBe(SUBJECT);
			expect(body.object).toBe(OBJECT);
			expect(body.action).toBe(ACTION);
		});

		test("resolves without a return value", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			const result = await client.addPolicy(TEST_POLICY);

			expect(result).toBeUndefined();
		});
	});

	describe("removePolicy", () => {
		test("throws when policy is undefined", async () => {
			await expect(client.removePolicy(undefined as never)).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.objectUndefined"
			});
		});

		test("sends POST to /{prefix}/policy/remove", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			await client.removePolicy(TEST_POLICY);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/policy/remove`);
			expect(options.method).toBe(HttpMethod.POST);
		});

		test("sends policy fields in the request body", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			await client.removePolicy(TEST_POLICY);

			const [, options] = fetchMock.mock.calls[0];
			const body = JSON.parse(options.body);
			expect(body.subject).toBe(SUBJECT);
			expect(body.object).toBe(OBJECT);
			expect(body.action).toBe(ACTION);
		});

		test("resolves without a return value", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			const result = await client.removePolicy(TEST_POLICY);

			expect(result).toBeUndefined();
		});
	});

	describe("getAllPolicies", () => {
		test("sends GET to /{prefix}/policy", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ entities: [], cursor: undefined }));

			await client.getAllPolicies();

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/policy`);
			expect(options.method).toBe(HttpMethod.GET);
		});

		test("returns entities and cursor from the response", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ entities: [TEST_POLICY], cursor: "10" }));

			const result = await client.getAllPolicies();

			expect(result.entities).toEqual([TEST_POLICY]);
			expect(result.cursor).toBe("10");
		});

		test("returns empty entities when no policies exist", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ entities: [] }));

			const result = await client.getAllPolicies();

			expect(result.entities).toEqual([]);
			expect(result.cursor).toBeUndefined();
		});

		test("passes subject, cursor, and limit as query params", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ entities: [] }));

			await client.getAllPolicies("alice", "5", 10);

			const [url] = fetchMock.mock.calls[0];
			expect(url).toContain("subject=alice");
			expect(url).toContain("cursor=5");
			expect(url).toContain("limit=10");
		});
	});

	describe("getAllRoles", () => {
		test("sends GET to /{prefix}/roles", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ roles: [] }));

			await client.getAllRoles();

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/roles`);
			expect(options.method).toBe(HttpMethod.GET);
		});

		test("returns roles and cursor from the response", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ roles: ["admin", "editor"], cursor: "2" }));

			const result = await client.getAllRoles();

			expect(result.roles).toEqual(["admin", "editor"]);
			expect(result.cursor).toBe("2");
		});

		test("returns empty roles when none exist", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ roles: [] }));

			const result = await client.getAllRoles();

			expect(result.roles).toEqual([]);
			expect(result.cursor).toBeUndefined();
		});

		test("passes cursor and limit as query params", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ roles: [] }));

			await client.getAllRoles("5", 10);

			const [url] = fetchMock.mock.calls[0];
			expect(url).toContain("cursor=5");
			expect(url).toContain("limit=10");
		});
	});

	describe("getPoliciesForSubject", () => {
		test("throws when subject is empty", async () => {
			await expect(client.getPoliciesForSubject("")).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("sends GET to /{prefix}/policy/:subject", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ policies: [] }));

			await client.getPoliciesForSubject(SUBJECT);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/policy/${SUBJECT}`);
			expect(options.method).toBe(HttpMethod.GET);
		});

		test("returns the policies for the subject", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ policies: [TEST_POLICY] }));

			const result = await client.getPoliciesForSubject(SUBJECT);

			expect(result).toEqual([TEST_POLICY]);
		});
	});

	describe("addRoleForSubject", () => {
		test("throws when subject is empty", async () => {
			await expect(client.addRoleForSubject("", ROLE)).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("throws when role is empty", async () => {
			await expect(client.addRoleForSubject(SUBJECT, "")).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("sends POST to /{prefix}/subject/:subject/role", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			await client.addRoleForSubject(SUBJECT, ROLE);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/subject/${SUBJECT}/role`);
			expect(options.method).toBe(HttpMethod.POST);
		});

		test("sends role in the request body", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			await client.addRoleForSubject(SUBJECT, ROLE);

			const [, options] = fetchMock.mock.calls[0];
			const body = JSON.parse(options.body);
			expect(body.role).toBe(ROLE);
		});

		test("resolves without a return value", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			const result = await client.addRoleForSubject(SUBJECT, ROLE);

			expect(result).toBeUndefined();
		});
	});

	describe("removeRoleForSubject", () => {
		test("throws when subject is empty", async () => {
			await expect(client.removeRoleForSubject("", ROLE)).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("throws when role is empty", async () => {
			await expect(client.removeRoleForSubject(SUBJECT, "")).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("sends DELETE to /{prefix}/subject/:subject/role/:role", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			await client.removeRoleForSubject(SUBJECT, ROLE);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/subject/${SUBJECT}/role/${ROLE}`);
			expect(options.method).toBe(HttpMethod.DELETE);
		});

		test("resolves without a return value", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			const result = await client.removeRoleForSubject(SUBJECT, ROLE);

			expect(result).toBeUndefined();
		});
	});

	describe("removeAllRolesForSubject", () => {
		test("throws when subject is empty", async () => {
			await expect(client.removeAllRolesForSubject("")).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("sends DELETE to /{prefix}/subject/:subject/roles", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			await client.removeAllRolesForSubject(SUBJECT);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/subject/${SUBJECT}/roles`);
			expect(options.method).toBe(HttpMethod.DELETE);
		});

		test("resolves without a return value", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			const result = await client.removeAllRolesForSubject(SUBJECT);

			expect(result).toBeUndefined();
		});
	});

	describe("getRolesForSubject", () => {
		test("throws when subject is empty", async () => {
			await expect(client.getRolesForSubject("")).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("sends GET to /{prefix}/subject/:subject/roles", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ roles: [] }));

			await client.getRolesForSubject(SUBJECT);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/subject/${SUBJECT}/roles`);
			expect(options.method).toBe(HttpMethod.GET);
		});

		test("returns the roles for the subject", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ roles: [ROLE] }));

			const result = await client.getRolesForSubject(SUBJECT);

			expect(result).toEqual([ROLE]);
		});
	});

	describe("getSubjectsForRole", () => {
		test("throws when role is empty", async () => {
			await expect(client.getSubjectsForRole("")).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("sends GET to /{prefix}/role/:role/subjects", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ subjects: [] }));

			await client.getSubjectsForRole(ROLE);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/role/${ROLE}/subjects`);
			expect(options.method).toBe(HttpMethod.GET);
		});

		test("returns the subjects for the role", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ subjects: [SUBJECT] }));

			const result = await client.getSubjectsForRole(ROLE);

			expect(result).toEqual([SUBJECT]);
		});
	});

	describe("hasRoleForSubject", () => {
		test("throws when subject is empty", async () => {
			await expect(client.hasRoleForSubject("", ROLE)).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("throws when role is empty", async () => {
			await expect(client.hasRoleForSubject(SUBJECT, "")).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("sends GET to /{prefix}/subject/:subject/role/:role", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ hasRole: true }));

			await client.hasRoleForSubject(SUBJECT, ROLE);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/subject/${SUBJECT}/role/${ROLE}`);
			expect(options.method).toBe(HttpMethod.GET);
		});

		test("returns true when the subject has the role", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ hasRole: true }));

			const result = await client.hasRoleForSubject(SUBJECT, ROLE);

			expect(result).toBe(true);
		});

		test("returns false when the subject does not have the role", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ hasRole: false }));

			const result = await client.hasRoleForSubject(SUBJECT, ROLE);

			expect(result).toBe(false);
		});
	});

	describe("addRoleInheritance", () => {
		test("throws when role is empty", async () => {
			await expect(client.addRoleInheritance("", PARENT_ROLE)).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("throws when parentRole is empty", async () => {
			await expect(client.addRoleInheritance(ROLE, "")).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("sends POST to /{prefix}/role/:role/inherit", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			await client.addRoleInheritance(ROLE, PARENT_ROLE);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/role/${ROLE}/inherit`);
			expect(options.method).toBe(HttpMethod.POST);
		});

		test("sends parentRole in the request body", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			await client.addRoleInheritance(ROLE, PARENT_ROLE);

			const [, options] = fetchMock.mock.calls[0];
			const body = JSON.parse(options.body);
			expect(body.parentRole).toBe(PARENT_ROLE);
		});

		test("resolves without a return value", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			const result = await client.addRoleInheritance(ROLE, PARENT_ROLE);

			expect(result).toBeUndefined();
		});
	});

	describe("removeRoleInheritance", () => {
		test("throws when role is empty", async () => {
			await expect(client.removeRoleInheritance("", PARENT_ROLE)).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("throws when parentRole is empty", async () => {
			await expect(client.removeRoleInheritance(ROLE, "")).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("sends DELETE to /{prefix}/role/:role/inherit/:parentRole", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			await client.removeRoleInheritance(ROLE, PARENT_ROLE);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/role/${ROLE}/inherit/${PARENT_ROLE}`);
			expect(options.method).toBe(HttpMethod.DELETE);
		});

		test("resolves without a return value", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			const result = await client.removeRoleInheritance(ROLE, PARENT_ROLE);

			expect(result).toBeUndefined();
		});
	});

	describe("getParentRoles", () => {
		test("throws when role is empty", async () => {
			await expect(client.getParentRoles("")).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("sends GET to /{prefix}/role/:role/parents", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ roles: [] }));

			await client.getParentRoles(ROLE);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/role/${ROLE}/parents`);
			expect(options.method).toBe(HttpMethod.GET);
		});

		test("returns the parent roles", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ roles: [PARENT_ROLE] }));

			const result = await client.getParentRoles(ROLE);

			expect(result).toEqual([PARENT_ROLE]);
		});
	});

	describe("getChildRoles", () => {
		test("throws when role is empty", async () => {
			await expect(client.getChildRoles("")).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("sends GET to /{prefix}/role/:role/children", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ roles: [] }));

			await client.getChildRoles(ROLE);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/role/${ROLE}/children`);
			expect(options.method).toBe(HttpMethod.GET);
		});

		test("returns the child roles", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ roles: [ROLE] }));

			const result = await client.getChildRoles(PARENT_ROLE);

			expect(result).toEqual([ROLE]);
		});
	});
});
