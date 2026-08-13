// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { ICasbinAuthorizationConnectorConfig } from "./ICasbinAuthorizationConnectorConfig.js";

/**
 * Options for the Casbin authorization connector constructor.
 */
export interface ICasbinAuthorizationConnectorConstructorOptions {
	/**
	 * The component type for the optional logging.
	 */
	loggingComponentType?: string;

	/**
	 * The configuration for the service.
	 */
	config: ICasbinAuthorizationConnectorConfig;
}
