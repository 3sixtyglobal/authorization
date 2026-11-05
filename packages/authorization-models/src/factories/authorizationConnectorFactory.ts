// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { Factory } from "@3sixty/core";
import type { IAuthorizationConnector } from "../models/IAuthorizationConnector.js";

/**
 * Factory for creating authorization connectors.
 */
export const AuthorizationConnectorFactory =
	Factory.createFactory<IAuthorizationConnector>("authorization-connector");
