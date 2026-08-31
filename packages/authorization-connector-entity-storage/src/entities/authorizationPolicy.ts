// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { entity, property } from "@twin.org/entity";

/**
 * Class describing an authorization policy entity stored in entity storage.
 */
@entity()
export class AuthorizationPolicy {
	/**
	 * The compound identifier for this policy rule, in
	 * "modelId|organization|subject|object|action" format.
	 */
	@property({ type: "string", isPrimary: true })
	public id!: string;

	/**
	 * The model identifier partitioning this policy.
	 */
	@property({ type: "string", isSecondary: true })
	public modelId!: string;

	/**
	 * The subject (user, service, or role) the policy applies to.
	 */
	@property({ type: "string", isSecondary: true })
	public subject!: string;

	/**
	 * The object the authorization policy applies to.
	 */
	@property({ type: "string" })
	public object!: string;

	/**
	 * The action the authorization policy allows.
	 */
	@property({ type: "string" })
	public action!: string;

	/**
	 * The organization the policy is scoped to, "*" for a global policy.
	 */
	@property({ type: "string", isSecondary: true })
	public organization!: string;
}
