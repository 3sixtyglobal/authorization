// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { entity, property } from "@3sixty/entity";

/**
 * Class describing an authorization role inheritance entity stored in entity storage.
 */
@entity()
export class AuthorizationRoleInheritance {
	/**
	 * The compound identifier for this inheritance relationship, in "modelId|role|inheritsFrom" format.
	 */
	@property({ type: "string", isPrimary: true, maxLength: 255 })
	public id!: string;

	/**
	 * The model identifier partitioning this inheritance.
	 */
	@property({ type: "string", maxLength: 255, isSecondary: true })
	public modelId!: string;

	/**
	 * The child role that inherits permissions from the parent.
	 */
	@property({ type: "string", maxLength: 128, isSecondary: true })
	public role!: string;

	/**
	 * The parent role whose permissions are inherited.
	 */
	@property({ type: "string", maxLength: 128, isSecondary: true })
	public inheritsFrom!: string;
}
