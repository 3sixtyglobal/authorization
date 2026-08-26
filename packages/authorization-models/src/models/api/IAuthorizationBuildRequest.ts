// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IAuthorizationModel } from "../IAuthorizationModel.js";

/**
 * Request to build an authorization model.
 */
export interface IAuthorizationBuildRequest {
	/**
	 * The request path parameters.
	 */
	pathParams: {
		/**
		 * The model identifier selecting which policy set to use.
		 */
		modelId: string;
	};

	/**
	 * The request data.
	 */
	body: IAuthorizationModel;
}
