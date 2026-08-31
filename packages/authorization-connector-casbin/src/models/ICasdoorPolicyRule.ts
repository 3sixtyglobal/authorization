// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * A raw policy rule row as returned by the Casdoor get-policies endpoint.
 * @internal
 */
export interface ICasdoorPolicyRule {
	/**
	 * The policy type: "p" for permission rules, "g" for grouping/role rules.
	 */
	Ptype: string;

	/**
	 * The first value in the rule (subject for "p"; subject or child role for "g").
	 */
	V0: string;

	/**
	 * The second value in the rule (object for "p"; parent role for "g").
	 */
	V1: string;

	/**
	 * The third value in the rule (action for "p"; organization scope for "g", empty for a
	 * global rule).
	 */
	V2: string;

	/**
	 * The fourth value in the rule (organization scope for "p", empty for a global rule;
	 * unused for "g").
	 */
	V3?: string;
}
