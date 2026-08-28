// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IAuthorizationServiceConfig } from "./IAuthorizationServiceConfig.js";

/**
 * Options for the authorization service constructor.
 */
export interface IAuthorizationServiceConstructorOptions {
	/**
	 * The component type for the optional logging component.
	 */
	loggingComponentType?: string;

	/**
	 * The component type for the optional telemetry component used for event metrics.
	 */
	telemetryComponentType?: string;

	/**
	 * The configuration for the service.
	 */
	config?: IAuthorizationServiceConfig;
}
