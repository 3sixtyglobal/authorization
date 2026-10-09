// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { entity, property } from "@3sixty/entity";

/**
 * Class describing a unique role name entity stored in entity storage.
 */
@entity()
export class AuthorizationRoleName {
	/**
	 * The compound identifier for this role name entry, in "modelId|name" format.
	 */
	@property({ type: "string", isPrimary: true, maxLength: 255 })
	public id!: string;

	/**
	 * The model identifier partitioning this role name.
	 */
	@property({ type: "string", maxLength: 255, isSecondary: true })
	public modelId!: string;

	/**
	 * The role name.
	 */
	@property({ type: "string", maxLength: 256, isSecondary: true })
	public name!: string;
}
