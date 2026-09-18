// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { entity, property } from "@twin.org/entity";

/**
 * Class describing an authorization policy entity stored in entity storage.
 */
@entity()
export class AuthorizationPolicy {
	/**
	 * The compound identifier for this policy rule, in "modelId|subject|object|action" format.
	 */
	@property({ type: "string", isPrimary: true, maxLength: 255 })
	public id!: string;

	/**
	 * The model identifier partitioning this policy.
	 */
	@property({ type: "string", maxLength: 255, isSecondary: true })
	public modelId!: string;

	/**
	 * The subject (user, service, or role) the policy applies to.
	 */
	@property({ type: "string", maxLength: 255, isSecondary: true })
	public subject!: string;

	/**
	 * The object the authorization policy applies to.
	 */
	@property({ type: "string", maxLength: 255 })
	public object!: string;

	/**
	 * The action the authorization policy allows.
	 */
	@property({ type: "string", maxLength: 128 })
	public action!: string;
}
