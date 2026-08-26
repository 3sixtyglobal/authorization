// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { entity, property } from "@twin.org/entity";

/**
 * Class describing an authorization role assignment entity stored in entity storage.
 */
@entity()
export class AuthorizationRoleAssignment {
	/**
	 * The compound identifier for this role assignment, in "modelId|subject|role" format.
	 */
	@property({ type: "string", isPrimary: true })
	public id!: string;

	/**
	 * The model identifier partitioning this assignment.
	 */
	@property({ type: "string", isSecondary: true })
	public modelId!: string;

	/**
	 * The subject (user or service) the role is assigned to.
	 */
	@property({ type: "string" })
	public subject!: string;

	/**
	 * The role assigned to the subject.
	 */
	@property({ type: "string" })
	public role!: string;
}
