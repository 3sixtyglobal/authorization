// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Response envelope returned by the Casbin server REST API.
 */
export interface ICasbinServerResponse<T> {
	/**
	 * The status of the response, either "ok" or "error".
	 */
	status: "ok" | "error";

	/**
	 * A message describing the result, populated on error.
	 */
	msg: string;

	/**
	 * The response payload.
	 */
	data: T;

	/**
	 * An optional secondary payload.
	 */
	data2: unknown;
}
