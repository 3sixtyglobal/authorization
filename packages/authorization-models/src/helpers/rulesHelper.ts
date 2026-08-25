// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { Is } from "@twin.org/core";
import type { IAuthorizationInheritance } from "../models/IAuthorizationInheritance.js";
import type { IAuthorizationPolicy } from "../models/IAuthorizationPolicy.js";
import type { IAuthorizationRules } from "../models/IAuthorizationRules.js";

/**
 * Helper class for working with authorization rules.
 */
export class RulesHelper {
	/**
	 * Builds an IAuthorizationRules object from a set of sources.
	 * @param sources The sources to build the rules from.
	 * @returns The constructed IAuthorizationRules object.
	 */
	public static buildRules(
		sources: {
			itemId: string;
			permissions: (string | { permission: string; inherits?: string[] })[];
			roles: (string | { role: string; inherits?: string[] })[];
		}[]
	): IAuthorizationRules {
		const policies: IAuthorizationPolicy[] = [];
		const roleInheritances: IAuthorizationInheritance[] = [];

		for (const source of sources) {
			const operationId = source.itemId;
			const permissions = source.permissions;
			const roles = source.roles;

			if (Is.arrayValue(permissions)) {
				const primaryPermissions: string[] = [];

				for (const entry of permissions) {
					const permission = Is.stringValue(entry) ? entry : entry.permission;
					primaryPermissions.push(permission);

					if (!policies.some(p => p.subject === permission && p.object === operationId)) {
						policies.push({ subject: permission, object: operationId, action: "execute" });
					}

					if (!Is.stringValue(entry)) {
						const inherits = entry.inherits;
						if (Is.arrayValue(inherits)) {
							for (const inherited of inherits) {
								if (
									!roleInheritances.some(r => r.role === permission && r.inheritsFrom === inherited)
								) {
									roleInheritances.push({ role: permission, inheritsFrom: inherited });
								}
							}
						}
					}
				}

				if (Is.arrayValue(roles)) {
					for (const entry of roles) {
						const role = Is.stringValue(entry) ? entry : entry.role;

						for (const permission of primaryPermissions) {
							if (!roleInheritances.some(r => r.role === role && r.inheritsFrom === permission)) {
								roleInheritances.push({ role, inheritsFrom: permission });
							}
						}

						if (!Is.stringValue(entry)) {
							const inherits = entry.inherits;
							if (Is.arrayValue(inherits)) {
								for (const inherited of inherits) {
									if (
										!roleInheritances.some(r => r.role === role && r.inheritsFrom === inherited)
									) {
										roleInheritances.push({ role, inheritsFrom: inherited });
									}
								}
							}
						}
					}
				}
			}
		}

		const roleSet = new Set(roleInheritances.map(r => r.role));
		const depthCache = new Map<string, number>();
		const nodeDepth = (node: string): number => {
			const cached = depthCache.get(node);
			if (cached !== undefined) {
				return cached;
			}
			if (!roleSet.has(node)) {
				depthCache.set(node, 0);
				return 0;
			}
			const d =
				1 +
				Math.max(
					0,
					...roleInheritances.filter(r => r.role === node).map(r => nodeDepth(r.inheritsFrom))
				);
			depthCache.set(node, d);
			return d;
		};
		roleInheritances.sort((a, b) => nodeDepth(a.role) - nodeDepth(b.role));

		return {
			policies,
			roleInheritances
		};
	}
}
