// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IAuthorizationProcessorConfig } from "./IAuthorizationProcessorConfig.js";

/**
 * Options for the AuthorizationProcessor constructor.
 */
export interface IAuthorizationProcessorConstructorOptions {
	/**
	 * The component to use for authorization of the root.
	 * @default authorization
	 */
	authorizationComponentType?: string;

	/**
	 * The configuration for the processor.
	 */
	config?: IAuthorizationProcessorConfig;
}
