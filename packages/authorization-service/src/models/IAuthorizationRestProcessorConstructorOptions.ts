// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IAuthorizationRestProcessorConfig } from "./IAuthorizationRestProcessorConfig.js";

/**
 * Options for the AuthorizationProcessor constructor.
 */
export interface IAuthorizationRestProcessorConstructorOptions {
	/**
	 * The component to use for authorization of the route.
	 * @default authorization
	 */
	authorizationComponentType?: string;

	/**
	 * The configuration for the processor.
	 */
	config?: IAuthorizationRestProcessorConfig;
}
