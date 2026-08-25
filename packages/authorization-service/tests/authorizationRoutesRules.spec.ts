// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { RulesHelper } from "@twin.org/authorization-models";
import { generateRestRoutesAuthorization } from "../src/authorizationRoutes.js";

describe("RulesHelper authorization route rules", () => {
	test("builds the expected policies and inheritances from the route permission and role definitions", () => {
		const routes = generateRestRoutesAuthorization("/authorization", "authorization");
		const result = RulesHelper.buildRules(
			routes.map(r => ({
				itemId: r.operationId,
				permissions: r.defaultPermissions ?? [],
				roles: r.defaultRoles ?? []
			}))
		);

		expect(result).toEqual({
			policies: [
				{ subject: "authorization:read", object: "authorizationCheck", action: "execute" },
				{ subject: "authorization:read", object: "authorizationCheckAny", action: "execute" },
				{ subject: "authorization:write", object: "authorizationAddPolicy", action: "execute" },
				{ subject: "authorization:write", object: "authorizationRemovePolicy", action: "execute" },
				{ subject: "authorization:read", object: "authorizationGetAllPolicies", action: "execute" },
				{ subject: "authorization:read", object: "authorizationGetAllRoles", action: "execute" },
				{ subject: "authorization:read", object: "authorizationHasRoles", action: "execute" },
				{
					subject: "authorization:read",
					object: "authorizationGetPoliciesForSubject",
					action: "execute"
				},
				{
					subject: "authorization:write",
					object: "authorizationAddRoleForSubject",
					action: "execute"
				},
				{
					subject: "authorization:write",
					object: "authorizationRemoveRoleForSubject",
					action: "execute"
				},
				{
					subject: "authorization:write",
					object: "authorizationRemoveAllRolesForSubject",
					action: "execute"
				},
				{
					subject: "authorization:read",
					object: "authorizationGetRolesForSubject",
					action: "execute"
				},
				{
					subject: "authorization:read",
					object: "authorizationHasRoleForSubject",
					action: "execute"
				},
				{
					subject: "authorization:read",
					object: "authorizationGetSubjectsForRole",
					action: "execute"
				},
				{
					subject: "authorization:write",
					object: "authorizationAddRoleInheritance",
					action: "execute"
				},
				{
					subject: "authorization:write",
					object: "authorizationRemoveRoleInheritance",
					action: "execute"
				},
				{ subject: "authorization:read", object: "authorizationGetParentRoles", action: "execute" },
				{ subject: "authorization:read", object: "authorizationGetChildRoles", action: "execute" }
			],
			roleInheritances: [
				{ role: "authorization-viewer", inheritsFrom: "authorization:read" },
				{ role: "authorization:write", inheritsFrom: "authorization:read" },
				{ role: "authorization-admin", inheritsFrom: "authorization:write" },
				{ role: "authorization-admin", inheritsFrom: "authorization-viewer" }
			]
		});
	});
});
