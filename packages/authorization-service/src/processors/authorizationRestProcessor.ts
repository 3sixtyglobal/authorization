// Copyright 2024 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import {
	HttpErrorHelper,
	type IBaseRoute,
	type IBaseRouteProcessor,
	type IHttpResponse,
	type IHttpServerRequest
} from "@twin.org/api-models";
import type { IAuthorizationComponent } from "@twin.org/authorization-models";
import { ContextIdKeys, type IContextIds } from "@twin.org/context";
import { BaseError, ComponentFactory, GeneralError, Is, UnauthorizedError } from "@twin.org/core";
import { nameof } from "@twin.org/nameof";
import { HttpStatusCode } from "@twin.org/web";
import type { IAuthorizationRestProcessorConstructorOptions } from "../models/IAuthorizationRestProcessorConstructorOptions.js";

/**
 * Use the identity from the context ids to check their authorization for a route.
 */
export class AuthorizationRestProcessor implements IBaseRouteProcessor {
	/**
	 * Runtime name for the class.
	 */
	public static readonly CLASS_NAME: string = nameof<AuthorizationRestProcessor>();

	/**
	 * The authorization component.
	 * @internal
	 */
	private readonly _authorizationComponent: IAuthorizationComponent;

	/**
	 * The model identifier used when checking route authorization.
	 * @internal
	 */
	private readonly _authorizationModelId: string;

	/**
	 * Include the stack with errors.
	 * @internal
	 */
	private readonly _includeErrorStack: boolean;

	/**
	 * Create a new instance of AuthorizationProcessor.
	 * @param options Options for the processor.
	 */
	constructor(options?: IAuthorizationRestProcessorConstructorOptions) {
		this._authorizationComponent = ComponentFactory.get(
			options?.authorizationComponentType ?? "authorization"
		);
		this._authorizationModelId = options?.config?.authorizationModelId ?? "rest";
		this._includeErrorStack = options?.config?.includeErrorStack ?? false;
	}

	/**
	 * Returns the class name of the component.
	 * @returns The class name of the component.
	 */
	public className(): string {
		return AuthorizationRestProcessor.CLASS_NAME;
	}

	/**
	 * Pre process the REST request for the specified route.
	 * @param request The incoming request.
	 * @param response The outgoing response.
	 * @param route The route to process.
	 * @param contextIds The context IDs of the request.
	 * @param processorState The state handed through the processors.
	 * @returns A promise that resolves when the JWT has been verified and the context populated, or an error response set.
	 */
	public async pre(
		request: IHttpServerRequest,
		response: IHttpResponse,
		route: IBaseRoute | undefined,
		contextIds: IContextIds,
		processorState: { [id: string]: unknown }
	): Promise<void> {
		if (!Is.empty(route) && (route.requiresAuthorization ?? true)) {
			try {
				const routeId = route.operationId;
				if (!Is.stringValue(routeId)) {
					throw new GeneralError(AuthorizationRestProcessor.CLASS_NAME, "routeIdMissing");
				}

				const userId = contextIds[ContextIdKeys.User];
				if (
					!Is.stringValue(userId) ||
					!(await this._authorizationComponent.check(
						this._authorizationModelId,
						userId,
						routeId,
						"execute"
					))
				) {
					throw new UnauthorizedError(AuthorizationRestProcessor.CLASS_NAME, "accessDenied");
				}
			} catch (err) {
				HttpErrorHelper.buildResponse(
					response,
					BaseError.fromError(err),
					HttpStatusCode.unauthorized,
					this._includeErrorStack
				);
			}
		}
	}
}
