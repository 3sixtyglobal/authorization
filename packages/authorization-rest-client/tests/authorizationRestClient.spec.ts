// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IAuthorizationModel } from "@3sixty/authorization-models";
import { GuardError } from "@3sixty/core";
import { HeaderTypes, HttpMethod, HttpStatusCode, MimeTypes } from "@3sixty/web";
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
const MODEL_ID = "default";

const SUBJECT = "user1";
const OBJECT = "/data";
const ACTION = "read";
const ROLE = "admin";
const PARENT_ROLE = "viewer";

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

	test("rejects when the response is not successful", async () => {
		fetchMock.mockResolvedValueOnce({
			ok: false,
			status: HttpStatusCode.internalServerError,
			statusText: "Internal Server Error",
			headers: new Headers({ [HeaderTypes.ContentType]: MimeTypes.Json }),
			json: async () => ({})
		});

		await expect(client.check(MODEL_ID, SUBJECT, OBJECT, ACTION)).rejects.toMatchObject({
			message: "baseRestClient.failureStatusText"
		});
	});

	describe("build", () => {
		const model: IAuthorizationModel = {
			policies: [{ subject: SUBJECT, object: OBJECT, action: ACTION }],
			roleInheritances: [{ role: ROLE, inheritsFrom: PARENT_ROLE }]
		};

		test("throws when modelId is empty", async () => {
			await expect(client.build("", model)).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("throws when model is missing", async () => {
			await expect(
				client.build(MODEL_ID, undefined as unknown as IAuthorizationModel)
			).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.objectUndefined"
			});
		});

		test("sends POST to /{prefix}/{modelId}", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			await client.build(MODEL_ID, model);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/${MODEL_ID}`);
			expect(options.method).toBe(HttpMethod.POST);
		});

		test("sends the model as the request body", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			await client.build(MODEL_ID, model);

			const [, options] = fetchMock.mock.calls[0];
			expect(JSON.parse(options.body)).toEqual(model);
		});

		test("resolves without a return value", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			const result = await client.build(MODEL_ID, model);

			expect(result).toBeUndefined();
		});
	});

	describe("check", () => {
		test("throws when modelId is empty", async () => {
			await expect(client.check("", SUBJECT, OBJECT, ACTION)).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("throws when subject is empty", async () => {
			await expect(client.check(MODEL_ID, "", OBJECT, ACTION)).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("throws when object is empty", async () => {
			await expect(client.check(MODEL_ID, SUBJECT, "", ACTION)).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("throws when action is empty", async () => {
			await expect(client.check(MODEL_ID, SUBJECT, OBJECT, "")).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("sends POST to /{prefix}/{modelId}/check", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ allowed: true }));

			await client.check(MODEL_ID, SUBJECT, OBJECT, ACTION);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/${MODEL_ID}/check`);
			expect(options.method).toBe(HttpMethod.POST);
		});

		test("sends subject, object and action in the request body", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ allowed: true }));

			await client.check(MODEL_ID, SUBJECT, OBJECT, ACTION);

			const [, options] = fetchMock.mock.calls[0];
			const body = JSON.parse(options.body);
			expect(body.subject).toBe(SUBJECT);
			expect(body.object).toBe(OBJECT);
			expect(body.action).toBe(ACTION);
		});

		test("returns true when allowed", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ allowed: true }));

			const result = await client.check(MODEL_ID, SUBJECT, OBJECT, ACTION);

			expect(result).toBe(true);
		});

		test("returns false when not allowed", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ allowed: false }));

			const result = await client.check(MODEL_ID, SUBJECT, OBJECT, ACTION);

			expect(result).toBe(false);
		});
	});

	describe("addPolicy", () => {
		test("throws when subject is empty", async () => {
			await expect(client.addPolicy(MODEL_ID, "", OBJECT, ACTION)).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("sends POST to /{prefix}/{modelId}/policy", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			await client.addPolicy(MODEL_ID, SUBJECT, OBJECT, ACTION);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/${MODEL_ID}/policy`);
			expect(options.method).toBe(HttpMethod.POST);
		});

		test("sends policy fields in the request body", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			await client.addPolicy(MODEL_ID, SUBJECT, OBJECT, ACTION);

			const [, options] = fetchMock.mock.calls[0];
			const body = JSON.parse(options.body);
			expect(body.subject).toBe(SUBJECT);
			expect(body.object).toBe(OBJECT);
			expect(body.action).toBe(ACTION);
		});

		test("resolves without a return value", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			const result = await client.addPolicy(MODEL_ID, SUBJECT, OBJECT, ACTION);

			expect(result).toBeUndefined();
		});
	});

	describe("removePolicy", () => {
		test("throws when subject is empty", async () => {
			await expect(client.removePolicy(MODEL_ID, "", OBJECT, ACTION)).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("sends POST to /{prefix}/{modelId}/policy/remove", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			await client.removePolicy(MODEL_ID, SUBJECT, OBJECT, ACTION);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/${MODEL_ID}/policy/remove`);
			expect(options.method).toBe(HttpMethod.POST);
		});

		test("sends policy fields in the request body", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			await client.removePolicy(MODEL_ID, SUBJECT, OBJECT, ACTION);

			const [, options] = fetchMock.mock.calls[0];
			const body = JSON.parse(options.body);
			expect(body.subject).toBe(SUBJECT);
			expect(body.object).toBe(OBJECT);
			expect(body.action).toBe(ACTION);
		});

		test("resolves without a return value", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			const result = await client.removePolicy(MODEL_ID, SUBJECT, OBJECT, ACTION);

			expect(result).toBeUndefined();
		});
	});

	describe("getAllPolicies", () => {
		test("sends GET to /{prefix}/{modelId}/policy", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ entities: [], cursor: undefined }));

			await client.getAllPolicies(MODEL_ID);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/${MODEL_ID}/policy`);
			expect(options.method).toBe(HttpMethod.GET);
		});

		test("returns entities and cursor from the response", async () => {
			fetchMock.mockResolvedValueOnce(
				jsonResponse({
					entities: [{ subject: SUBJECT, object: OBJECT, action: ACTION }],
					cursor: "10"
				})
			);

			const result = await client.getAllPolicies(MODEL_ID);

			expect(result.entities).toEqual([{ subject: SUBJECT, object: OBJECT, action: ACTION }]);
			expect(result.cursor).toBe("10");
		});

		test("returns empty entities when no policies exist", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ entities: [] }));

			const result = await client.getAllPolicies(MODEL_ID);

			expect(result.entities).toEqual([]);
			expect(result.cursor).toBeUndefined();
		});

		test("passes subject, cursor, and limit as query params", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ entities: [] }));

			await client.getAllPolicies(MODEL_ID, "alice", "5", 10);

			const [url] = fetchMock.mock.calls[0];
			expect(url).toContain("subject=alice");
			expect(url).toContain("cursor=5");
			expect(url).toContain("limit=10");
		});

		test("passes only subject when cursor and limit are omitted", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ entities: [] }));

			await client.getAllPolicies(MODEL_ID, "alice");

			const [url] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/${MODEL_ID}/policy?subject=alice`);
		});

		test("encodes query values that need encoding", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ entities: [] }));

			await client.getAllPolicies(MODEL_ID, "a/b c%d", "x&y=z");

			const [url] = fetchMock.mock.calls[0];
			expect(url).toBe(
				`${ENDPOINT}/${PREFIX}/${MODEL_ID}/policy?subject=a%2Fb%20c%25d&cursor=x%26y%3Dz`
			);
		});
	});

	describe("getAllRoles", () => {
		test("sends GET to /{prefix}/{modelId}/roles", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ roles: [] }));

			await client.getAllRoles(MODEL_ID);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/${MODEL_ID}/roles`);
			expect(options.method).toBe(HttpMethod.GET);
		});

		test("returns roles and cursor from the response", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ roles: ["admin", "editor"], cursor: "2" }));

			const result = await client.getAllRoles(MODEL_ID);

			expect(result.roles).toEqual(["admin", "editor"]);
			expect(result.cursor).toBe("2");
		});

		test("returns empty roles when none exist", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ roles: [] }));

			const result = await client.getAllRoles(MODEL_ID);

			expect(result.roles).toEqual([]);
			expect(result.cursor).toBeUndefined();
		});

		test("passes cursor and limit as query params", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ roles: [] }));

			await client.getAllRoles(MODEL_ID, "5", 10);

			const [url] = fetchMock.mock.calls[0];
			expect(url).toContain("cursor=5");
			expect(url).toContain("limit=10");
		});
	});

	describe("getPoliciesForSubject", () => {
		test("throws when subject is empty", async () => {
			await expect(client.getPoliciesForSubject(MODEL_ID, "")).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("sends GET to /{prefix}/{modelId}/policy/:subject", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ entities: [] }));

			await client.getPoliciesForSubject(MODEL_ID, SUBJECT);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/${MODEL_ID}/policy/${SUBJECT}`);
			expect(options.method).toBe(HttpMethod.GET);
		});

		test("returns the policies for the subject", async () => {
			fetchMock.mockResolvedValueOnce(
				jsonResponse({ entities: [{ subject: SUBJECT, object: OBJECT, action: ACTION }] })
			);

			const result = await client.getPoliciesForSubject(MODEL_ID, SUBJECT);

			expect(result).toEqual({ entities: [{ subject: SUBJECT, object: OBJECT, action: ACTION }] });
		});

		test("passes cursor and limit as query params", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ entities: [] }));

			await client.getPoliciesForSubject(MODEL_ID, SUBJECT, "5", 10);

			const [url] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/${MODEL_ID}/policy/${SUBJECT}?cursor=5&limit=10`);
		});

		test("encodes the subject path param and cursor query value", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ entities: [] }));

			await client.getPoliciesForSubject(MODEL_ID, "a/b c%d", "x&y=z");

			const [url] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/${MODEL_ID}/policy/a%2Fb%20c%25d?cursor=x%26y%3Dz`);
		});
	});

	describe("addRoleForSubject", () => {
		test("throws when subject is empty", async () => {
			await expect(client.addRoleForSubject(MODEL_ID, "", ROLE)).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("throws when role is empty", async () => {
			await expect(client.addRoleForSubject(MODEL_ID, SUBJECT, "")).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("sends POST to /{prefix}/{modelId}/subject/:subject/role", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			await client.addRoleForSubject(MODEL_ID, SUBJECT, ROLE);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/${MODEL_ID}/subject/${SUBJECT}/role`);
			expect(options.method).toBe(HttpMethod.POST);
		});

		test("sends role in the request body", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			await client.addRoleForSubject(MODEL_ID, SUBJECT, ROLE);

			const [, options] = fetchMock.mock.calls[0];
			const body = JSON.parse(options.body);
			expect(body.role).toBe(ROLE);
		});

		test("resolves without a return value", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			const result = await client.addRoleForSubject(MODEL_ID, SUBJECT, ROLE);

			expect(result).toBeUndefined();
		});
	});

	describe("removeRoleForSubject", () => {
		test("throws when subject is empty", async () => {
			await expect(client.removeRoleForSubject(MODEL_ID, "", ROLE)).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("throws when role is empty", async () => {
			await expect(client.removeRoleForSubject(MODEL_ID, SUBJECT, "")).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("sends DELETE to /{prefix}/{modelId}/subject/:subject/role/:role", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			await client.removeRoleForSubject(MODEL_ID, SUBJECT, ROLE);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/${MODEL_ID}/subject/${SUBJECT}/role/${ROLE}`);
			expect(options.method).toBe(HttpMethod.DELETE);
		});

		test("resolves without a return value", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			const result = await client.removeRoleForSubject(MODEL_ID, SUBJECT, ROLE);

			expect(result).toBeUndefined();
		});
	});

	describe("removeAllRolesForSubject", () => {
		test("throws when subject is empty", async () => {
			await expect(client.removeAllRolesForSubject(MODEL_ID, "")).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("sends DELETE to /{prefix}/{modelId}/subject/:subject/roles", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			await client.removeAllRolesForSubject(MODEL_ID, SUBJECT);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/${MODEL_ID}/subject/${SUBJECT}/roles`);
			expect(options.method).toBe(HttpMethod.DELETE);
		});

		test("resolves without a return value", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			const result = await client.removeAllRolesForSubject(MODEL_ID, SUBJECT);

			expect(result).toBeUndefined();
		});
	});

	describe("getRolesForSubject", () => {
		test("throws when subject is empty", async () => {
			await expect(client.getRolesForSubject(MODEL_ID, "")).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("sends GET to /{prefix}/{modelId}/subject/:subject/roles", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ roles: [] }));

			await client.getRolesForSubject(MODEL_ID, SUBJECT);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/${MODEL_ID}/subject/${SUBJECT}/roles`);
			expect(options.method).toBe(HttpMethod.GET);
		});

		test("returns the roles for the subject", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ roles: [ROLE] }));

			const result = await client.getRolesForSubject(MODEL_ID, SUBJECT);

			expect(result).toEqual([ROLE]);
		});
	});

	describe("getSubjectsForRole", () => {
		test("throws when role is empty", async () => {
			await expect(client.getSubjectsForRole(MODEL_ID, "")).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("sends GET to /{prefix}/{modelId}/role/:role/subjects", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ subjects: [] }));

			await client.getSubjectsForRole(MODEL_ID, ROLE);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/${MODEL_ID}/role/${ROLE}/subjects`);
			expect(options.method).toBe(HttpMethod.GET);
		});

		test("returns the subjects for the role", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ subjects: [SUBJECT] }));

			const result = await client.getSubjectsForRole(MODEL_ID, ROLE);

			expect(result).toEqual([SUBJECT]);
		});
	});

	describe("hasRoleForSubject", () => {
		test("throws when subject is empty", async () => {
			await expect(client.hasRoleForSubject(MODEL_ID, "", ROLE)).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("throws when role is empty", async () => {
			await expect(client.hasRoleForSubject(MODEL_ID, SUBJECT, "")).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("sends GET to /{prefix}/{modelId}/subject/:subject/role/:role", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ hasRole: true }));

			await client.hasRoleForSubject(MODEL_ID, SUBJECT, ROLE);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/${MODEL_ID}/subject/${SUBJECT}/role/${ROLE}`);
			expect(options.method).toBe(HttpMethod.GET);
		});

		test("returns true when the subject has the role", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ hasRole: true }));

			const result = await client.hasRoleForSubject(MODEL_ID, SUBJECT, ROLE);

			expect(result).toBe(true);
		});

		test("returns false when the subject does not have the role", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ hasRole: false }));

			const result = await client.hasRoleForSubject(MODEL_ID, SUBJECT, ROLE);

			expect(result).toBe(false);
		});
	});

	describe("addRoleInheritance", () => {
		test("throws when role is empty", async () => {
			await expect(client.addRoleInheritance(MODEL_ID, "", PARENT_ROLE)).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("throws when inheritsFrom is empty", async () => {
			await expect(client.addRoleInheritance(MODEL_ID, ROLE, "")).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("sends POST to /{prefix}/{modelId}/role/:role/inherit", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			await client.addRoleInheritance(MODEL_ID, ROLE, PARENT_ROLE);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/${MODEL_ID}/role/${ROLE}/inherit`);
			expect(options.method).toBe(HttpMethod.POST);
		});

		test("sends inheritsFrom in the request body", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			await client.addRoleInheritance(MODEL_ID, ROLE, PARENT_ROLE);

			const [, options] = fetchMock.mock.calls[0];
			const body = JSON.parse(options.body);
			expect(body.inheritsFrom).toBe(PARENT_ROLE);
		});

		test("resolves without a return value", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			const result = await client.addRoleInheritance(MODEL_ID, ROLE, PARENT_ROLE);

			expect(result).toBeUndefined();
		});
	});

	describe("removeRoleInheritance", () => {
		test("throws when role is empty", async () => {
			await expect(client.removeRoleInheritance(MODEL_ID, "", PARENT_ROLE)).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("throws when inheritsFrom is empty", async () => {
			await expect(client.removeRoleInheritance(MODEL_ID, ROLE, "")).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("sends DELETE to /{prefix}/{modelId}/role/:role/inherit/:inheritsFrom", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			await client.removeRoleInheritance(MODEL_ID, ROLE, PARENT_ROLE);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/${MODEL_ID}/role/${ROLE}/inherit/${PARENT_ROLE}`);
			expect(options.method).toBe(HttpMethod.DELETE);
		});

		test("resolves without a return value", async () => {
			fetchMock.mockResolvedValueOnce(noContentResponse());

			const result = await client.removeRoleInheritance(MODEL_ID, ROLE, PARENT_ROLE);

			expect(result).toBeUndefined();
		});
	});

	describe("getParentRoles", () => {
		test("throws when role is empty", async () => {
			await expect(client.getParentRoles(MODEL_ID, "")).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("sends GET to /{prefix}/{modelId}/role/:role/parents", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ roles: [] }));

			await client.getParentRoles(MODEL_ID, ROLE);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/${MODEL_ID}/role/${ROLE}/parents`);
			expect(options.method).toBe(HttpMethod.GET);
		});

		test("returns the parent roles", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ roles: [PARENT_ROLE] }));

			const result = await client.getParentRoles(MODEL_ID, ROLE);

			expect(result).toEqual([PARENT_ROLE]);
		});
	});

	describe("getChildRoles", () => {
		test("throws when role is empty", async () => {
			await expect(client.getChildRoles(MODEL_ID, "")).rejects.toMatchObject({
				name: GuardError.CLASS_NAME,
				message: "guard.stringEmpty"
			});
		});

		test("sends GET to /{prefix}/{modelId}/role/:role/children", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ roles: [] }));

			await client.getChildRoles(MODEL_ID, ROLE);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/${MODEL_ID}/role/${ROLE}/children`);
			expect(options.method).toBe(HttpMethod.GET);
		});

		test("returns the child roles", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ roles: [ROLE] }));

			const result = await client.getChildRoles(MODEL_ID, PARENT_ROLE);

			expect(result).toEqual([ROLE]);
		});
	});

	describe("hasRoles", () => {
		test("sends POST to /{prefix}/{modelId}/roles/has", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ exists: [true, false] }));

			await client.hasRoles(MODEL_ID, [ROLE, "missing"]);

			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe(`${ENDPOINT}/${PREFIX}/${MODEL_ID}/roles/has`);
			expect(options.method).toBe(HttpMethod.POST);
		});

		test("sends roles in the request body", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ exists: [true] }));

			await client.hasRoles(MODEL_ID, [ROLE]);

			const body = JSON.parse(fetchMock.mock.calls[0][1].body);
			expect(body).toEqual({ roles: [ROLE] });
		});

		test("returns the exists array", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ exists: [true, false] }));

			const result = await client.hasRoles(MODEL_ID, [ROLE, "missing"]);

			expect(result).toEqual([true, false]);
		});

		test("returns empty array for empty input", async () => {
			fetchMock.mockResolvedValueOnce(jsonResponse({ exists: [] }));

			const result = await client.hasRoles(MODEL_ID, []);

			expect(result).toEqual([]);
		});
	});
});
