// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IRestRouteEntryPoint } from "@3sixty/api-models";
import { generateRestRoutesAuthorization, tagsAuthorization } from "./authorizationRoutes.js";

/**
 * REST entry points for the authorization service.
 */
export const restEntryPoints: IRestRouteEntryPoint[] = [
	{
		name: "authorization",
		defaultBaseRoute: "authorization",
		tags: tagsAuthorization,
		generateRoutes: generateRestRoutesAuthorization
	}
];
