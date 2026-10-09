// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { entity, property } from "@3sixty/entity";

/**
 * Class describing an authorization role assignment entity stored in entity storage.
 */
@entity()
export class AuthorizationRoleAssignment {
	/**
	 * The compound identifier for this role assignment, in "modelId|subject|role" format.
	 */
	@property({ type: "string", isPrimary: true, maxLength: 255 })
	public id!: string;

	/**
	 * The model identifier partitioning this assignment.
	 */
	@property({ type: "string", maxLength: 255, isSecondary: true })
	public modelId!: string;

	/**
	 * The subject (user or service) the role is assigned to.
	 */
	@property({ type: "string", maxLength: 255, isSecondary: true })
	public subject!: string;

	/**
	 * The role assigned to the subject.
	 */
	@property({ type: "string", maxLength: 128, isSecondary: true })
	public role!: string;
}
