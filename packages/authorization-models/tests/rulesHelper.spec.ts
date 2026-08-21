// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { RulesHelper } from "../src/helpers/rulesHelper.js";

describe("RulesHelper", () => {
	describe("buildRules", () => {
		describe("empty and edge cases", () => {
			test("returns empty rules when sources array is empty", () => {
				const result = RulesHelper.buildRules([]);
				expect(result.policies ?? []).toEqual([]);
				expect(result.roleInheritances ?? []).toEqual([]);
			});

			test("returns empty rules when source has empty permissions and roles", () => {
				const result = RulesHelper.buildRules([{ itemId: "op1", permissions: [], roles: [] }]);
				expect(result.policies ?? []).toEqual([]);
				expect(result.roleInheritances ?? []).toEqual([]);
			});

			test("returns empty rules when permissions array is empty even if roles are provided", () => {
				const result = RulesHelper.buildRules([
					{ itemId: "op1", permissions: [], roles: ["viewer"] }
				]);
				expect(result.policies ?? []).toEqual([]);
				expect(result.roleInheritances ?? []).toEqual([]);
			});
		});

		describe("policy creation", () => {
			test("creates a policy for a string permission", () => {
				const result = RulesHelper.buildRules([
					{ itemId: "op1", permissions: ["read"], roles: [] }
				]);
				expect(result.policies ?? []).toEqual([
					{ subject: "read", object: "op1", action: "execute" }
				]);
			});

			test("creates a policy for an object permission entry", () => {
				const result = RulesHelper.buildRules([
					{ itemId: "op1", permissions: [{ permission: "write" }], roles: [] }
				]);
				expect(result.policies ?? []).toEqual([
					{ subject: "write", object: "op1", action: "execute" }
				]);
			});

			test("creates policies for multiple permissions on the same item", () => {
				const result = RulesHelper.buildRules([
					{ itemId: "op1", permissions: ["read", "list"], roles: [] }
				]);
				expect(result.policies ?? []).toEqual([
					{ subject: "read", object: "op1", action: "execute" },
					{ subject: "list", object: "op1", action: "execute" }
				]);
			});

			test("creates separate policies per item when the same permission covers multiple items", () => {
				const result = RulesHelper.buildRules([
					{ itemId: "op1", permissions: ["read"], roles: [] },
					{ itemId: "op2", permissions: ["read"], roles: [] }
				]);
				expect(result.policies ?? []).toEqual([
					{ subject: "read", object: "op1", action: "execute" },
					{ subject: "read", object: "op2", action: "execute" }
				]);
			});

			test("does not duplicate a policy when the same permission and item appear in two sources", () => {
				const result = RulesHelper.buildRules([
					{ itemId: "op1", permissions: ["read"], roles: [] },
					{ itemId: "op1", permissions: ["read"], roles: [] }
				]);
				expect(result.policies ?? []).toHaveLength(1);
				expect((result.policies ?? [])[0]).toEqual({
					subject: "read",
					object: "op1",
					action: "execute"
				});
			});
		});

		describe("permission inheritance", () => {
			test("adds an inheritance when a permission entry specifies inherits", () => {
				const result = RulesHelper.buildRules([
					{
						itemId: "op1",
						permissions: [{ permission: "write", inherits: ["read"] }],
						roles: []
					}
				]);
				expect(result.roleInheritances ?? []).toEqual([{ role: "write", inheritsFrom: "read" }]);
			});

			test("adds multiple inheritances for a permission with multiple inherits", () => {
				const result = RulesHelper.buildRules([
					{
						itemId: "op1",
						permissions: [{ permission: "admin", inherits: ["write", "read"] }],
						roles: []
					}
				]);
				expect(result.roleInheritances ?? []).toEqual([
					{ role: "admin", inheritsFrom: "write" },
					{ role: "admin", inheritsFrom: "read" }
				]);
			});

			test("adds inheritances for multiple permissions that each have inherits", () => {
				const result = RulesHelper.buildRules([
					{
						itemId: "op1",
						permissions: [
							{ permission: "write", inherits: ["read"] },
							{ permission: "admin", inherits: ["write"] }
						],
						roles: []
					}
				]);
				expect(result.roleInheritances ?? []).toContainEqual({
					role: "write",
					inheritsFrom: "read"
				});
				expect(result.roleInheritances ?? []).toContainEqual({
					role: "admin",
					inheritsFrom: "write"
				});
			});

			test("does not add a permission inherits entry when the inherits array is empty", () => {
				const result = RulesHelper.buildRules([
					{
						itemId: "op1",
						permissions: [{ permission: "write", inherits: [] }],
						roles: []
					}
				]);
				expect(result.roleInheritances ?? []).toEqual([]);
			});

			test("does not duplicate a permission inheritance added by two sources", () => {
				const result = RulesHelper.buildRules([
					{
						itemId: "op1",
						permissions: [{ permission: "write", inherits: ["read"] }],
						roles: []
					},
					{
						itemId: "op2",
						permissions: [{ permission: "write", inherits: ["read"] }],
						roles: []
					}
				]);
				const inheritances = (result.roleInheritances ?? []).filter(
					r => r.role === "write" && r.inheritsFrom === "read"
				);
				expect(inheritances).toHaveLength(1);
			});

			test("does not add inheritance for a string permission entry even if roles are present", () => {
				const result = RulesHelper.buildRules([
					{ itemId: "op1", permissions: ["read"], roles: ["viewer"] }
				]);
				expect((result.roleInheritances ?? []).some(r => r.role === "read")).toBe(false);
			});
		});

		describe("role-to-permission linking", () => {
			test("links a string role to a string permission", () => {
				const result = RulesHelper.buildRules([
					{ itemId: "op1", permissions: ["read"], roles: ["viewer"] }
				]);
				expect(result.roleInheritances ?? []).toEqual([{ role: "viewer", inheritsFrom: "read" }]);
			});

			test("links a string role to each permission when multiple permissions are listed", () => {
				const result = RulesHelper.buildRules([
					{ itemId: "op1", permissions: ["read", "list"], roles: ["viewer"] }
				]);
				expect(result.roleInheritances ?? []).toContainEqual({
					role: "viewer",
					inheritsFrom: "read"
				});
				expect(result.roleInheritances ?? []).toContainEqual({
					role: "viewer",
					inheritsFrom: "list"
				});
			});

			test("links multiple roles to the same permission", () => {
				const result = RulesHelper.buildRules([
					{ itemId: "op1", permissions: ["read"], roles: ["viewer", "auditor"] }
				]);
				expect(result.roleInheritances ?? []).toContainEqual({
					role: "viewer",
					inheritsFrom: "read"
				});
				expect(result.roleInheritances ?? []).toContainEqual({
					role: "auditor",
					inheritsFrom: "read"
				});
			});

			test("links an object role entry to the permission", () => {
				const result = RulesHelper.buildRules([
					{
						itemId: "op1",
						permissions: ["write"],
						roles: [{ role: "admin", inherits: [] }]
					}
				]);
				expect(result.roleInheritances ?? []).toContainEqual({
					role: "admin",
					inheritsFrom: "write"
				});
			});

			test("does not duplicate a role-permission link across sources", () => {
				const result = RulesHelper.buildRules([
					{ itemId: "op1", permissions: ["read"], roles: ["viewer"] },
					{ itemId: "op2", permissions: ["read"], roles: ["viewer"] }
				]);
				const links = (result.roleInheritances ?? []).filter(
					r => r.role === "viewer" && r.inheritsFrom === "read"
				);
				expect(links).toHaveLength(1);
			});
		});

		describe("role inheritance", () => {
			test("adds a role inheritance when a role entry specifies inherits", () => {
				const result = RulesHelper.buildRules([
					{
						itemId: "op1",
						permissions: ["write"],
						roles: [{ role: "admin", inherits: ["viewer"] }]
					}
				]);
				expect(result.roleInheritances ?? []).toContainEqual({
					role: "admin",
					inheritsFrom: "viewer"
				});
			});

			test("adds multiple role inheritances when a role entry has multiple inherits", () => {
				const result = RulesHelper.buildRules([
					{
						itemId: "op1",
						permissions: ["write"],
						roles: [{ role: "superadmin", inherits: ["admin", "viewer"] }]
					}
				]);
				expect(result.roleInheritances ?? []).toContainEqual({
					role: "superadmin",
					inheritsFrom: "admin"
				});
				expect(result.roleInheritances ?? []).toContainEqual({
					role: "superadmin",
					inheritsFrom: "viewer"
				});
			});

			test("does not add a role inheritance entry when role inherits array is empty", () => {
				const result = RulesHelper.buildRules([
					{
						itemId: "op1",
						permissions: ["write"],
						roles: [{ role: "admin", inherits: [] }]
					}
				]);
				expect(
					(result.roleInheritances ?? []).some(
						r => r.role === "admin" && r.inheritsFrom === "admin"
					)
				).toBe(false);
			});

			test("does not duplicate a role inheritance added by two sources", () => {
				const result = RulesHelper.buildRules([
					{
						itemId: "op1",
						permissions: ["write"],
						roles: [{ role: "admin", inherits: ["viewer"] }]
					},
					{
						itemId: "op2",
						permissions: ["write"],
						roles: [{ role: "admin", inherits: ["viewer"] }]
					}
				]);
				const links = (result.roleInheritances ?? []).filter(
					r => r.role === "admin" && r.inheritsFrom === "viewer"
				);
				expect(links).toHaveLength(1);
			});
		});

		describe("combined scenarios", () => {
			test("produces correct rules for the typical reader/writer route pattern", () => {
				const result = RulesHelper.buildRules([
					{
						itemId: "authorization:check",
						permissions: ["authorization:read"],
						roles: ["authorization-viewer"]
					},
					{
						itemId: "authorization:addPolicy",
						permissions: [{ permission: "authorization:write", inherits: ["authorization:read"] }],
						roles: [{ role: "authorization-admin", inherits: ["authorization-viewer"] }]
					}
				]);

				expect(result.policies ?? []).toContainEqual({
					subject: "authorization:read",
					object: "authorization:check",
					action: "execute"
				});
				expect(result.policies ?? []).toContainEqual({
					subject: "authorization:write",
					object: "authorization:addPolicy",
					action: "execute"
				});

				expect(result.roleInheritances ?? []).toContainEqual({
					role: "authorization-viewer",
					inheritsFrom: "authorization:read"
				});
				expect(result.roleInheritances ?? []).toContainEqual({
					role: "authorization:write",
					inheritsFrom: "authorization:read"
				});
				expect(result.roleInheritances ?? []).toContainEqual({
					role: "authorization-admin",
					inheritsFrom: "authorization:write"
				});
				expect(result.roleInheritances ?? []).toContainEqual({
					role: "authorization-admin",
					inheritsFrom: "authorization-viewer"
				});
			});

			test("multiple sources with different permissions produce all expected policies", () => {
				const result = RulesHelper.buildRules([
					{ itemId: "op1", permissions: ["read"], roles: [] },
					{ itemId: "op2", permissions: ["write"], roles: [] },
					{ itemId: "op3", permissions: ["read", "write"], roles: [] }
				]);
				expect(result.policies ?? []).toHaveLength(4);
				expect(result.policies ?? []).toContainEqual({
					subject: "read",
					object: "op1",
					action: "execute"
				});
				expect(result.policies ?? []).toContainEqual({
					subject: "write",
					object: "op2",
					action: "execute"
				});
				expect(result.policies ?? []).toContainEqual({
					subject: "read",
					object: "op3",
					action: "execute"
				});
				expect(result.policies ?? []).toContainEqual({
					subject: "write",
					object: "op3",
					action: "execute"
				});
			});

			test("role linked to permission from one source is not re-added for a second source with the same permission", () => {
				const result = RulesHelper.buildRules([
					{ itemId: "op1", permissions: ["read"], roles: ["viewer"] },
					{ itemId: "op2", permissions: ["read"], roles: ["viewer"] }
				]);
				const links = (result.roleInheritances ?? []).filter(r => r.role === "viewer");
				expect(links).toHaveLength(1);
			});

			test("all output arrays are defined even with a minimal source", () => {
				const result = RulesHelper.buildRules([
					{ itemId: "op1", permissions: ["read"], roles: [] }
				]);
				expect(Array.isArray(result.policies ?? [])).toBe(true);
				expect(Array.isArray(result.roleInheritances ?? [])).toBe(true);
			});
		});
	});
});
