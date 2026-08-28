// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IAuthorizationRouteProcessorConfig } from "./IAuthorizationRouteProcessorConfig.js";

/**
 * Options for the AuthorizationRouteProcessor constructor.
 */
export interface IAuthorizationRouteProcessorConstructorOptions {
	/**
	 * The component to use for authorization of the route.
	 * @default authorization
	 */
	authorizationComponentType?: string;

	/**
	 * The configuration for the processor.
	 */
	config?: IAuthorizationRouteProcessorConfig;
}
