// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { EntitySchemaFactory, EntitySchemaHelper } from "@twin.org/entity";
import { nameof } from "@twin.org/nameof";
import { AuthorizationPolicy } from "./entities/authorizationPolicy.js";
import { AuthorizationRoleAssignment } from "./entities/authorizationRoleAssignment.js";
import { AuthorizationRoleInheritance } from "./entities/authorizationRoleInheritance.js";

/**
 * Initialize the schema for the authorization entity storage connector.
 */
export function initSchema(): void {
	EntitySchemaFactory.register(nameof<AuthorizationPolicy>(), () =>
		EntitySchemaHelper.getSchema(AuthorizationPolicy)
	);
	EntitySchemaFactory.register(nameof<AuthorizationRoleAssignment>(), () =>
		EntitySchemaHelper.getSchema(AuthorizationRoleAssignment)
	);
	EntitySchemaFactory.register(nameof<AuthorizationRoleInheritance>(), () =>
		EntitySchemaHelper.getSchema(AuthorizationRoleInheritance)
	);
}
