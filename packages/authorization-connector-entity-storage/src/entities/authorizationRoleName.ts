// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { entity, property } from "@twin.org/entity";

/**
 * Class describing a unique role name entity stored in entity storage.
 */
@entity()
export class AuthorizationRoleName {
	/**
	 * The role name, used as the primary key to guarantee uniqueness.
	 */
	@property({ type: "string", isPrimary: true })
	public id!: string;
}
