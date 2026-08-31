// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Defines a single authorization policy rule binding a subject, object, and action.
 */
export interface IAuthorizationPolicy {
	/**
	 * The subject (user, service, or role) the policy applies to.
	 */
	subject: string;

	/**
	 * The object the policy applies to.
	 */
	object: string;

	/**
	 * The action the policy controls.
	 */
	action: string;

	/**
	 * The organization the policy is scoped to, omitted for a global policy.
	 */
	organization?: string;
}
