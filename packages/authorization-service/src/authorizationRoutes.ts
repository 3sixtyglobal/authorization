// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type {
	IHttpRequestContext,
	INoContentResponse,
	IRestRoute,
	IRouteAuthorization,
	ITag
} from "@twin.org/api-models";
import type {
	IAuthorizationAddPolicyRequest,
	IAuthorizationAddRoleForSubjectRequest,
	IAuthorizationAddRoleInheritanceRequest,
	IAuthorizationCheckRequest,
	IAuthorizationCheckResponse,
	IAuthorizationComponent,
	IAuthorizationGetAllPoliciesRequest,
	IAuthorizationGetAllPoliciesResponse,
	IAuthorizationGetAllRolesRequest,
	IAuthorizationGetAllRolesResponse,
	IAuthorizationGetChildRolesRequest,
	IAuthorizationGetChildRolesResponse,
	IAuthorizationGetParentRolesRequest,
	IAuthorizationGetParentRolesResponse,
	IAuthorizationGetPoliciesForSubjectRequest,
	IAuthorizationGetPoliciesForSubjectResponse,
	IAuthorizationGetRolesForSubjectRequest,
	IAuthorizationGetRolesForSubjectResponse,
	IAuthorizationGetSubjectsForRoleRequest,
	IAuthorizationGetSubjectsForRoleResponse,
	IAuthorizationHasRoleForSubjectRequest,
	IAuthorizationHasRoleForSubjectResponse,
	IAuthorizationHasRolesRequest,
	IAuthorizationHasRolesResponse,
	IAuthorizationRemoveAllRolesForSubjectRequest,
	IAuthorizationRemovePolicyRequest,
	IAuthorizationRemoveRoleForSubjectRequest,
	IAuthorizationRemoveRoleInheritanceRequest
} from "@twin.org/authorization-models";
import { Coerce, ComponentFactory, Guards } from "@twin.org/core";
import { nameof } from "@twin.org/nameof";
import { HttpStatusCode } from "@twin.org/web";

const ROUTES_SOURCE = "authorizationRoutes";

/**
 * The default authorization for the routes, used to seed authorization rules.
 */
const DEFAULT_AUTHORIZATION_READER: IRouteAuthorization = {
	permission: "tenant:read",
	role: "authorization-admin"
};
const DEFAULT_AUTHORIZATION_WRITER: IRouteAuthorization = {
	permission: "tenant:write",
	role: "authorization-admin",
	inherits: [DEFAULT_AUTHORIZATION_READER.permission]
};

/**
 * The tag to associate with the routes.
 */
export const tagsAuthorization: ITag[] = [
	{
		name: "Authorization",
		description: "Endpoints which are modelled to access an authorization service."
	}
];

/**
 * The REST routes for authorization.
 * @param baseRouteName Prefix to prepend to the paths.
 * @param componentName The name of the component to use in the routes stored in the ComponentFactory.
 * @returns The generated routes.
 */
export function generateRestRoutesAuthorization(
	baseRouteName: string,
	componentName: string
): IRestRoute[] {
	const checkRoute: IRestRoute<IAuthorizationCheckRequest, IAuthorizationCheckResponse> = {
		operationId: "authorizationCheck",
		summary: "Check an authorization policy",
		tag: tagsAuthorization[0].name,
		method: "POST",
		path: `${baseRouteName}/:modelId/check`,
		handler: async (httpRequestContext, request) =>
			authorizationCheck(httpRequestContext, componentName, request),
		requestType: {
			type: nameof<IAuthorizationCheckRequest>(),
			examples: [
				{
					id: "authorizationCheckExample",
					request: {
						pathParams: {
							modelId: "default"
						},
						body: {
							subject: "user1",
							object: "/data",
							action: "read"
						}
					}
				}
			]
		},
		responseType: [
			{
				type: nameof<IAuthorizationCheckResponse>(),
				examples: [
					{
						id: "authorizationCheckResponseExample",
						response: {
							body: {
								allowed: true
							}
						}
					}
				]
			}
		],
		defaultAuthorization: DEFAULT_AUTHORIZATION_READER
	};

	const addPolicyRoute: IRestRoute<IAuthorizationAddPolicyRequest, INoContentResponse> = {
		operationId: "authorizationAddPolicy",
		summary: "Add an authorization policy",
		tag: tagsAuthorization[0].name,
		method: "POST",
		path: `${baseRouteName}/:modelId/policy`,
		handler: async (httpRequestContext, request) =>
			authorizationAddPolicy(httpRequestContext, componentName, request),
		requestType: {
			type: nameof<IAuthorizationAddPolicyRequest>(),
			examples: [
				{
					id: "authorizationAddPolicyExample",
					request: {
						pathParams: {
							modelId: "default"
						},
						body: {
							subject: "user1",
							object: "/data",
							action: "read"
						}
					}
				}
			]
		},
		responseType: [
			{
				type: nameof<INoContentResponse>(),
				examples: [
					{
						id: "authorizationAddPolicyResponseExample",
						response: {
							statusCode: HttpStatusCode.noContent
						}
					}
				]
			}
		],
		defaultAuthorization: DEFAULT_AUTHORIZATION_WRITER
	};

	const removePolicyRoute: IRestRoute<IAuthorizationRemovePolicyRequest, INoContentResponse> = {
		operationId: "authorizationRemovePolicy",
		summary: "Remove an authorization policy",
		tag: tagsAuthorization[0].name,
		method: "POST",
		path: `${baseRouteName}/:modelId/policy/remove`,
		handler: async (httpRequestContext, request) =>
			authorizationRemovePolicy(httpRequestContext, componentName, request),
		requestType: {
			type: nameof<IAuthorizationRemovePolicyRequest>(),
			examples: [
				{
					id: "authorizationRemovePolicyExample",
					request: {
						pathParams: {
							modelId: "default"
						},
						body: {
							subject: "user1",
							object: "/data",
							action: "read"
						}
					}
				}
			]
		},
		responseType: [
			{
				type: nameof<INoContentResponse>(),
				examples: [
					{
						id: "authorizationRemovePolicyResponseExample",
						response: {
							statusCode: HttpStatusCode.noContent
						}
					}
				]
			}
		],
		defaultAuthorization: DEFAULT_AUTHORIZATION_WRITER
	};

	const getAllPoliciesRoute: IRestRoute<
		IAuthorizationGetAllPoliciesRequest,
		IAuthorizationGetAllPoliciesResponse
	> = {
		operationId: "authorizationGetAllPolicies",
		summary: "Get all authorization policies",
		tag: tagsAuthorization[0].name,
		method: "GET",
		path: `${baseRouteName}/:modelId/policy`,
		handler: async (httpRequestContext, request) =>
			authorizationGetAllPolicies(httpRequestContext, componentName, request),
		requestType: {
			type: nameof<IAuthorizationGetAllPoliciesRequest>(),
			examples: [
				{
					id: "authorizationGetAllPoliciesExample",
					request: {
						pathParams: { modelId: "default" },
						query: { subject: "user1", limit: "20" }
					}
				}
			]
		},
		responseType: [
			{
				type: nameof<IAuthorizationGetAllPoliciesResponse>(),
				examples: [
					{
						id: "authorizationGetAllPoliciesResponseExample",
						response: {
							body: {
								entities: [{ subject: "user1", object: "/data", action: "read" }]
							}
						}
					}
				]
			}
		],
		defaultAuthorization: DEFAULT_AUTHORIZATION_READER
	};

	const getAllRolesRoute: IRestRoute<
		IAuthorizationGetAllRolesRequest,
		IAuthorizationGetAllRolesResponse
	> = {
		operationId: "authorizationGetAllRoles",
		summary: "Get all authorization roles",
		tag: tagsAuthorization[0].name,
		method: "GET",
		path: `${baseRouteName}/:modelId/roles`,
		handler: async (httpRequestContext, request) =>
			authorizationGetAllRoles(httpRequestContext, componentName, request),
		requestType: {
			type: nameof<IAuthorizationGetAllRolesRequest>(),
			examples: [
				{
					id: "authorizationGetAllRolesExample",
					request: {
						pathParams: { modelId: "default" },
						query: { limit: "20" }
					}
				}
			]
		},
		responseType: [
			{
				type: nameof<IAuthorizationGetAllRolesResponse>(),
				examples: [
					{
						id: "authorizationGetAllRolesResponseExample",
						response: {
							body: {
								roles: ["admin", "editor", "viewer"]
							}
						}
					}
				]
			}
		],
		defaultAuthorization: DEFAULT_AUTHORIZATION_READER
	};

	const hasRolesRoute: IRestRoute<IAuthorizationHasRolesRequest, IAuthorizationHasRolesResponse> = {
		operationId: "authorizationHasRoles",
		summary: "Check whether a list of roles exist in the system",
		tag: tagsAuthorization[0].name,
		method: "POST",
		path: `${baseRouteName}/:modelId/roles/has`,
		handler: async (httpRequestContext, request) =>
			authorizationHasRoles(httpRequestContext, componentName, request),
		requestType: {
			type: nameof<IAuthorizationHasRolesRequest>(),
			examples: [
				{
					id: "authorizationHasRolesExample",
					request: {
						pathParams: { modelId: "default" },
						body: {
							roles: ["admin", "editor", "unknown-role"]
						}
					}
				}
			]
		},
		responseType: [
			{
				type: nameof<IAuthorizationHasRolesResponse>(),
				examples: [
					{
						id: "authorizationHasRolesResponseExample",
						response: {
							body: {
								exists: [true, true, false]
							}
						}
					}
				]
			}
		],
		defaultAuthorization: DEFAULT_AUTHORIZATION_READER
	};

	const getPoliciesForSubjectRoute: IRestRoute<
		IAuthorizationGetPoliciesForSubjectRequest,
		IAuthorizationGetPoliciesForSubjectResponse
	> = {
		operationId: "authorizationGetPoliciesForSubject",
		summary: "Get authorization policies for a subject",
		tag: tagsAuthorization[0].name,
		method: "GET",
		path: `${baseRouteName}/:modelId/policy/:subject`,
		handler: async (httpRequestContext, request) =>
			authorizationGetPoliciesForSubject(httpRequestContext, componentName, request),
		requestType: {
			type: nameof<IAuthorizationGetPoliciesForSubjectRequest>(),
			examples: [
				{
					id: "authorizationGetPoliciesForSubjectExample",
					request: {
						pathParams: {
							modelId: "default",
							subject: "user1"
						}
					}
				}
			]
		},
		responseType: [
			{
				type: nameof<IAuthorizationGetPoliciesForSubjectResponse>(),
				examples: [
					{
						id: "authorizationGetPoliciesForSubjectResponseExample",
						response: {
							body: {
								entities: [{ subject: "user1", object: "/data", action: "read" }]
							}
						}
					}
				]
			}
		],
		defaultAuthorization: DEFAULT_AUTHORIZATION_READER
	};

	const addRoleForSubjectRoute: IRestRoute<
		IAuthorizationAddRoleForSubjectRequest,
		INoContentResponse
	> = {
		operationId: "authorizationAddRoleForSubject",
		summary: "Add a role for a subject",
		tag: tagsAuthorization[0].name,
		method: "POST",
		path: `${baseRouteName}/:modelId/subject/:subject/role`,
		handler: async (httpRequestContext, request) =>
			authorizationAddRoleForSubject(httpRequestContext, componentName, request),
		requestType: {
			type: nameof<IAuthorizationAddRoleForSubjectRequest>(),
			examples: [
				{
					id: "authorizationAddRoleForSubjectExample",
					request: {
						pathParams: { modelId: "default", subject: "user1" },
						body: { role: "admin" }
					}
				}
			]
		},
		responseType: [
			{
				type: nameof<INoContentResponse>(),
				examples: [
					{
						id: "authorizationAddRoleForSubjectResponseExample",
						response: { statusCode: HttpStatusCode.noContent }
					}
				]
			}
		],
		defaultAuthorization: DEFAULT_AUTHORIZATION_WRITER
	};

	const removeRoleForSubjectRoute: IRestRoute<
		IAuthorizationRemoveRoleForSubjectRequest,
		INoContentResponse
	> = {
		operationId: "authorizationRemoveRoleForSubject",
		summary: "Remove a role for a subject",
		tag: tagsAuthorization[0].name,
		method: "DELETE",
		path: `${baseRouteName}/:modelId/subject/:subject/role/:role`,
		handler: async (httpRequestContext, request) =>
			authorizationRemoveRoleForSubject(httpRequestContext, componentName, request),
		requestType: {
			type: nameof<IAuthorizationRemoveRoleForSubjectRequest>(),
			examples: [
				{
					id: "authorizationRemoveRoleForSubjectExample",
					request: {
						pathParams: { modelId: "default", subject: "user1", role: "admin" }
					}
				}
			]
		},
		responseType: [
			{
				type: nameof<INoContentResponse>(),
				examples: [
					{
						id: "authorizationRemoveRoleForSubjectResponseExample",
						response: { statusCode: HttpStatusCode.noContent }
					}
				]
			}
		],
		defaultAuthorization: DEFAULT_AUTHORIZATION_WRITER
	};

	const removeAllRolesForSubjectRoute: IRestRoute<
		IAuthorizationRemoveAllRolesForSubjectRequest,
		INoContentResponse
	> = {
		operationId: "authorizationRemoveAllRolesForSubject",
		summary: "Remove all roles for a subject",
		tag: tagsAuthorization[0].name,
		method: "DELETE",
		path: `${baseRouteName}/:modelId/subject/:subject/roles`,
		handler: async (httpRequestContext, request) =>
			authorizationRemoveAllRolesForSubject(httpRequestContext, componentName, request),
		requestType: {
			type: nameof<IAuthorizationRemoveAllRolesForSubjectRequest>(),
			examples: [
				{
					id: "authorizationRemoveAllRolesForSubjectExample",
					request: {
						pathParams: { modelId: "default", subject: "user1" }
					}
				}
			]
		},
		responseType: [
			{
				type: nameof<INoContentResponse>(),
				examples: [
					{
						id: "authorizationRemoveAllRolesForSubjectResponseExample",
						response: { statusCode: HttpStatusCode.noContent }
					}
				]
			}
		],
		defaultAuthorization: DEFAULT_AUTHORIZATION_WRITER
	};

	const getRolesForSubjectRoute: IRestRoute<
		IAuthorizationGetRolesForSubjectRequest,
		IAuthorizationGetRolesForSubjectResponse
	> = {
		operationId: "authorizationGetRolesForSubject",
		summary: "Get roles for a subject",
		tag: tagsAuthorization[0].name,
		method: "GET",
		path: `${baseRouteName}/:modelId/subject/:subject/roles`,
		handler: async (httpRequestContext, request) =>
			authorizationGetRolesForSubject(httpRequestContext, componentName, request),
		requestType: {
			type: nameof<IAuthorizationGetRolesForSubjectRequest>(),
			examples: [
				{
					id: "authorizationGetRolesForSubjectExample",
					request: {
						pathParams: { modelId: "default", subject: "user1" }
					}
				}
			]
		},
		responseType: [
			{
				type: nameof<IAuthorizationGetRolesForSubjectResponse>(),
				examples: [
					{
						id: "authorizationGetRolesForSubjectResponseExample",
						response: {
							body: { roles: ["admin", "editor"] }
						}
					}
				]
			}
		],
		defaultAuthorization: DEFAULT_AUTHORIZATION_READER
	};

	const hasRoleForSubjectRoute: IRestRoute<
		IAuthorizationHasRoleForSubjectRequest,
		IAuthorizationHasRoleForSubjectResponse
	> = {
		operationId: "authorizationHasRoleForSubject",
		summary: "Check if a subject has a role",
		tag: tagsAuthorization[0].name,
		method: "GET",
		path: `${baseRouteName}/:modelId/subject/:subject/role/:role`,
		handler: async (httpRequestContext, request) =>
			authorizationHasRoleForSubject(httpRequestContext, componentName, request),
		requestType: {
			type: nameof<IAuthorizationHasRoleForSubjectRequest>(),
			examples: [
				{
					id: "authorizationHasRoleForSubjectExample",
					request: {
						pathParams: { modelId: "default", subject: "user1", role: "admin" }
					}
				}
			]
		},
		responseType: [
			{
				type: nameof<IAuthorizationHasRoleForSubjectResponse>(),
				examples: [
					{
						id: "authorizationHasRoleForSubjectResponseExample",
						response: {
							body: { hasRole: true }
						}
					}
				]
			}
		],
		defaultAuthorization: DEFAULT_AUTHORIZATION_READER
	};

	const getSubjectsForRoleRoute: IRestRoute<
		IAuthorizationGetSubjectsForRoleRequest,
		IAuthorizationGetSubjectsForRoleResponse
	> = {
		operationId: "authorizationGetSubjectsForRole",
		summary: "Get subjects for a role",
		tag: tagsAuthorization[0].name,
		method: "GET",
		path: `${baseRouteName}/:modelId/role/:role/subjects`,
		handler: async (httpRequestContext, request) =>
			authorizationGetSubjectsForRole(httpRequestContext, componentName, request),
		requestType: {
			type: nameof<IAuthorizationGetSubjectsForRoleRequest>(),
			examples: [
				{
					id: "authorizationGetSubjectsForRoleExample",
					request: {
						pathParams: { modelId: "default", role: "admin" }
					}
				}
			]
		},
		responseType: [
			{
				type: nameof<IAuthorizationGetSubjectsForRoleResponse>(),
				examples: [
					{
						id: "authorizationGetSubjectsForRoleResponseExample",
						response: {
							body: { subjects: ["user1", "user2"] }
						}
					}
				]
			}
		],
		defaultAuthorization: DEFAULT_AUTHORIZATION_READER
	};

	const addRoleInheritanceRoute: IRestRoute<
		IAuthorizationAddRoleInheritanceRequest,
		INoContentResponse
	> = {
		operationId: "authorizationAddRoleInheritance",
		summary: "Add a role inheritance",
		tag: tagsAuthorization[0].name,
		method: "POST",
		path: `${baseRouteName}/:modelId/role/:role/inherit`,
		handler: async (httpRequestContext, request) =>
			authorizationAddRoleInheritance(httpRequestContext, componentName, request),
		requestType: {
			type: nameof<IAuthorizationAddRoleInheritanceRequest>(),
			examples: [
				{
					id: "authorizationAddRoleInheritanceExample",
					request: {
						pathParams: { modelId: "default", role: "editor" },
						body: { inheritsFrom: "viewer" }
					}
				}
			]
		},
		responseType: [
			{
				type: nameof<INoContentResponse>(),
				examples: [
					{
						id: "authorizationAddRoleInheritanceResponseExample",
						response: { statusCode: HttpStatusCode.noContent }
					}
				]
			}
		],
		defaultAuthorization: DEFAULT_AUTHORIZATION_WRITER
	};

	const removeRoleInheritanceRoute: IRestRoute<
		IAuthorizationRemoveRoleInheritanceRequest,
		INoContentResponse
	> = {
		operationId: "authorizationRemoveRoleInheritance",
		summary: "Remove a role inheritance",
		tag: tagsAuthorization[0].name,
		method: "DELETE",
		path: `${baseRouteName}/:modelId/role/:role/inherit/:inheritsFrom`,
		handler: async (httpRequestContext, request) =>
			authorizationRemoveRoleInheritance(httpRequestContext, componentName, request),
		requestType: {
			type: nameof<IAuthorizationRemoveRoleInheritanceRequest>(),
			examples: [
				{
					id: "authorizationRemoveRoleInheritanceExample",
					request: {
						pathParams: { modelId: "default", role: "editor", inheritsFrom: "viewer" }
					}
				}
			]
		},
		responseType: [
			{
				type: nameof<INoContentResponse>(),
				examples: [
					{
						id: "authorizationRemoveRoleInheritanceResponseExample",
						response: { statusCode: HttpStatusCode.noContent }
					}
				]
			}
		],
		defaultAuthorization: DEFAULT_AUTHORIZATION_WRITER
	};

	const getParentRolesRoute: IRestRoute<
		IAuthorizationGetParentRolesRequest,
		IAuthorizationGetParentRolesResponse
	> = {
		operationId: "authorizationGetParentRoles",
		summary: "Get parent roles for a role",
		tag: tagsAuthorization[0].name,
		method: "GET",
		path: `${baseRouteName}/:modelId/role/:role/parents`,
		handler: async (httpRequestContext, request) =>
			authorizationGetParentRoles(httpRequestContext, componentName, request),
		requestType: {
			type: nameof<IAuthorizationGetParentRolesRequest>(),
			examples: [
				{
					id: "authorizationGetParentRolesExample",
					request: {
						pathParams: { modelId: "default", role: "editor" }
					}
				}
			]
		},
		responseType: [
			{
				type: nameof<IAuthorizationGetParentRolesResponse>(),
				examples: [
					{
						id: "authorizationGetParentRolesResponseExample",
						response: {
							body: { roles: ["viewer"] }
						}
					}
				]
			}
		],
		defaultAuthorization: DEFAULT_AUTHORIZATION_READER
	};

	const getChildRolesRoute: IRestRoute<
		IAuthorizationGetChildRolesRequest,
		IAuthorizationGetChildRolesResponse
	> = {
		operationId: "authorizationGetChildRoles",
		summary: "Get child roles for a role",
		tag: tagsAuthorization[0].name,
		method: "GET",
		path: `${baseRouteName}/:modelId/role/:role/children`,
		handler: async (httpRequestContext, request) =>
			authorizationGetChildRoles(httpRequestContext, componentName, request),
		requestType: {
			type: nameof<IAuthorizationGetChildRolesRequest>(),
			examples: [
				{
					id: "authorizationGetChildRolesExample",
					request: {
						pathParams: { modelId: "default", role: "admin" }
					}
				}
			]
		},
		responseType: [
			{
				type: nameof<IAuthorizationGetChildRolesResponse>(),
				examples: [
					{
						id: "authorizationGetChildRolesResponseExample",
						response: {
							body: { roles: ["editor", "viewer"] }
						}
					}
				]
			}
		],
		defaultAuthorization: DEFAULT_AUTHORIZATION_READER
	};

	return [
		checkRoute,
		addPolicyRoute,
		removePolicyRoute,
		getAllPoliciesRoute,
		getAllRolesRoute,
		hasRolesRoute,
		getPoliciesForSubjectRoute,
		addRoleForSubjectRoute,
		removeRoleForSubjectRoute,
		removeAllRolesForSubjectRoute,
		getRolesForSubjectRoute,
		hasRoleForSubjectRoute,
		getSubjectsForRoleRoute,
		addRoleInheritanceRoute,
		removeRoleInheritanceRoute,
		getParentRolesRoute,
		getChildRolesRoute
	];
}

/**
 * Perform the check authorization operation.
 * @param httpRequestContext The request context for the API.
 * @param componentName The name of the component to use in the routes.
 * @param request The request.
 * @returns The response object with additional http response properties.
 */
export async function authorizationCheck(
	httpRequestContext: IHttpRequestContext,
	componentName: string,
	request: IAuthorizationCheckRequest
): Promise<IAuthorizationCheckResponse> {
	Guards.object<IAuthorizationCheckRequest>(ROUTES_SOURCE, nameof(request), request);
	Guards.object<IAuthorizationCheckRequest["pathParams"]>(
		ROUTES_SOURCE,
		nameof(request.pathParams),
		request.pathParams
	);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.modelId), request.pathParams.modelId);
	Guards.object<IAuthorizationCheckRequest["body"]>(
		ROUTES_SOURCE,
		nameof(request.body),
		request.body
	);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.body.subject), request.body.subject);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.body.object), request.body.object);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.body.action), request.body.action);

	const component = ComponentFactory.get<IAuthorizationComponent>(componentName);
	const allowed = await component.check(
		request.pathParams.modelId,
		request.body.subject,
		request.body.object,
		request.body.action
	);

	return { body: { allowed } };
}

/**
 * Perform the add policy operation.
 * @param httpRequestContext The request context for the API.
 * @param componentName The name of the component to use in the routes.
 * @param request The request.
 * @returns The response object with additional http response properties.
 */
export async function authorizationAddPolicy(
	httpRequestContext: IHttpRequestContext,
	componentName: string,
	request: IAuthorizationAddPolicyRequest
): Promise<INoContentResponse> {
	Guards.object<IAuthorizationAddPolicyRequest>(ROUTES_SOURCE, nameof(request), request);
	Guards.object<IAuthorizationAddPolicyRequest["pathParams"]>(
		ROUTES_SOURCE,
		nameof(request.pathParams),
		request.pathParams
	);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.modelId), request.pathParams.modelId);
	Guards.object<IAuthorizationAddPolicyRequest["body"]>(
		ROUTES_SOURCE,
		nameof(request.body),
		request.body
	);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.body.subject), request.body.subject);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.body.object), request.body.object);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.body.action), request.body.action);

	const component = ComponentFactory.get<IAuthorizationComponent>(componentName);
	await component.addPolicy(
		request.pathParams.modelId,
		request.body.subject,
		request.body.object,
		request.body.action
	);

	return { statusCode: HttpStatusCode.noContent };
}

/**
 * Perform the remove policy operation.
 * @param httpRequestContext The request context for the API.
 * @param componentName The name of the component to use in the routes.
 * @param request The request.
 * @returns The response object with additional http response properties.
 */
export async function authorizationRemovePolicy(
	httpRequestContext: IHttpRequestContext,
	componentName: string,
	request: IAuthorizationRemovePolicyRequest
): Promise<INoContentResponse> {
	Guards.object<IAuthorizationRemovePolicyRequest>(ROUTES_SOURCE, nameof(request), request);
	Guards.object<IAuthorizationRemovePolicyRequest["pathParams"]>(
		ROUTES_SOURCE,
		nameof(request.pathParams),
		request.pathParams
	);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.modelId), request.pathParams.modelId);
	Guards.object<IAuthorizationRemovePolicyRequest["body"]>(
		ROUTES_SOURCE,
		nameof(request.body),
		request.body
	);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.body.subject), request.body.subject);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.body.object), request.body.object);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.body.action), request.body.action);

	const component = ComponentFactory.get<IAuthorizationComponent>(componentName);
	await component.removePolicy(
		request.pathParams.modelId,
		request.body.subject,
		request.body.object,
		request.body.action
	);

	return { statusCode: HttpStatusCode.noContent };
}

/**
 * Perform the get all policies operation.
 * @param httpRequestContext The request context for the API.
 * @param componentName The name of the component to use in the routes.
 * @param request The request.
 * @returns The response object with additional http response properties.
 */
export async function authorizationGetAllPolicies(
	httpRequestContext: IHttpRequestContext,
	componentName: string,
	request: IAuthorizationGetAllPoliciesRequest
): Promise<IAuthorizationGetAllPoliciesResponse> {
	Guards.object<IAuthorizationGetAllPoliciesRequest>(ROUTES_SOURCE, nameof(request), request);
	Guards.object<IAuthorizationGetAllPoliciesRequest["pathParams"]>(
		ROUTES_SOURCE,
		nameof(request.pathParams),
		request.pathParams
	);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.modelId), request.pathParams.modelId);

	const component = ComponentFactory.get<IAuthorizationComponent>(componentName);
	const limit = request.query?.limit !== undefined ? parseInt(request.query.limit, 10) : undefined;
	const result = await component.getAllPolicies(
		request.pathParams.modelId,
		request.query?.subject,
		request.query?.cursor,
		limit
	);

	return { body: result };
}

/**
 * Perform the get all roles operation.
 * @param httpRequestContext The request context for the API.
 * @param componentName The name of the component to use in the routes.
 * @param request The request.
 * @returns The response object with additional http response properties.
 */
export async function authorizationGetAllRoles(
	httpRequestContext: IHttpRequestContext,
	componentName: string,
	request: IAuthorizationGetAllRolesRequest
): Promise<IAuthorizationGetAllRolesResponse> {
	Guards.object<IAuthorizationGetAllRolesRequest>(ROUTES_SOURCE, nameof(request), request);
	Guards.object<IAuthorizationGetAllRolesRequest["pathParams"]>(
		ROUTES_SOURCE,
		nameof(request.pathParams),
		request.pathParams
	);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.modelId), request.pathParams.modelId);

	const component = ComponentFactory.get<IAuthorizationComponent>(componentName);
	const limit = request.query?.limit !== undefined ? parseInt(request.query.limit, 10) : undefined;
	const result = await component.getAllRoles(
		request.pathParams.modelId,
		request.query?.cursor,
		limit
	);

	return { body: result };
}

/**
 * Perform the has roles operation.
 * @param httpRequestContext The request context for the API.
 * @param componentName The name of the component to use in the routes.
 * @param request The request.
 * @returns The response object with additional http response properties.
 */
export async function authorizationHasRoles(
	httpRequestContext: IHttpRequestContext,
	componentName: string,
	request: IAuthorizationHasRolesRequest
): Promise<IAuthorizationHasRolesResponse> {
	Guards.object<IAuthorizationHasRolesRequest>(ROUTES_SOURCE, nameof(request), request);
	Guards.object<IAuthorizationHasRolesRequest["pathParams"]>(
		ROUTES_SOURCE,
		nameof(request.pathParams),
		request.pathParams
	);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.modelId), request.pathParams.modelId);
	Guards.object<IAuthorizationHasRolesRequest["body"]>(
		ROUTES_SOURCE,
		nameof(request.body),
		request.body
	);
	Guards.array<string>(ROUTES_SOURCE, nameof(request.body.roles), request.body.roles);

	const component = ComponentFactory.get<IAuthorizationComponent>(componentName);
	const exists = await component.hasRoles(request.pathParams.modelId, request.body.roles);

	return { body: { exists } };
}

/**
 * Perform the get policies for subject operation.
 * @param httpRequestContext The request context for the API.
 * @param componentName The name of the component to use in the routes.
 * @param request The request.
 * @returns The response object with additional http response properties.
 */
export async function authorizationGetPoliciesForSubject(
	httpRequestContext: IHttpRequestContext,
	componentName: string,
	request: IAuthorizationGetPoliciesForSubjectRequest
): Promise<IAuthorizationGetPoliciesForSubjectResponse> {
	Guards.object<IAuthorizationGetPoliciesForSubjectRequest>(
		ROUTES_SOURCE,
		nameof(request),
		request
	);
	Guards.object<IAuthorizationGetPoliciesForSubjectRequest["pathParams"]>(
		ROUTES_SOURCE,
		nameof(request.pathParams),
		request.pathParams
	);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.modelId), request.pathParams.modelId);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.subject), request.pathParams.subject);

	const component = ComponentFactory.get<IAuthorizationComponent>(componentName);
	const result = await component.getPoliciesForSubject(
		request.pathParams.modelId,
		request.pathParams.subject,
		request.query?.cursor,
		Coerce.integer(request.query?.limit)
	);

	return { body: result };
}

/**
 * Perform the add role for subject operation.
 * @param httpRequestContext The request context for the API.
 * @param componentName The name of the component to use in the routes.
 * @param request The request.
 * @returns The response object with additional http response properties.
 */
export async function authorizationAddRoleForSubject(
	httpRequestContext: IHttpRequestContext,
	componentName: string,
	request: IAuthorizationAddRoleForSubjectRequest
): Promise<INoContentResponse> {
	Guards.object<IAuthorizationAddRoleForSubjectRequest>(ROUTES_SOURCE, nameof(request), request);
	Guards.object<IAuthorizationAddRoleForSubjectRequest["pathParams"]>(
		ROUTES_SOURCE,
		nameof(request.pathParams),
		request.pathParams
	);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.modelId), request.pathParams.modelId);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.subject), request.pathParams.subject);
	Guards.object<IAuthorizationAddRoleForSubjectRequest["body"]>(
		ROUTES_SOURCE,
		nameof(request.body),
		request.body
	);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.body.role), request.body.role);

	const component = ComponentFactory.get<IAuthorizationComponent>(componentName);
	await component.addRoleForSubject(
		request.pathParams.modelId,
		request.pathParams.subject,
		request.body.role
	);

	return { statusCode: HttpStatusCode.noContent };
}

/**
 * Perform the remove role for subject operation.
 * @param httpRequestContext The request context for the API.
 * @param componentName The name of the component to use in the routes.
 * @param request The request.
 * @returns The response object with additional http response properties.
 */
export async function authorizationRemoveRoleForSubject(
	httpRequestContext: IHttpRequestContext,
	componentName: string,
	request: IAuthorizationRemoveRoleForSubjectRequest
): Promise<INoContentResponse> {
	Guards.object<IAuthorizationRemoveRoleForSubjectRequest>(ROUTES_SOURCE, nameof(request), request);
	Guards.object<IAuthorizationRemoveRoleForSubjectRequest["pathParams"]>(
		ROUTES_SOURCE,
		nameof(request.pathParams),
		request.pathParams
	);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.modelId), request.pathParams.modelId);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.subject), request.pathParams.subject);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.role), request.pathParams.role);

	const component = ComponentFactory.get<IAuthorizationComponent>(componentName);
	await component.removeRoleForSubject(
		request.pathParams.modelId,
		request.pathParams.subject,
		request.pathParams.role
	);

	return { statusCode: HttpStatusCode.noContent };
}

/**
 * Perform the remove all roles for subject operation.
 * @param httpRequestContext The request context for the API.
 * @param componentName The name of the component to use in the routes.
 * @param request The request.
 * @returns The response object with additional http response properties.
 */
export async function authorizationRemoveAllRolesForSubject(
	httpRequestContext: IHttpRequestContext,
	componentName: string,
	request: IAuthorizationRemoveAllRolesForSubjectRequest
): Promise<INoContentResponse> {
	Guards.object<IAuthorizationRemoveAllRolesForSubjectRequest>(
		ROUTES_SOURCE,
		nameof(request),
		request
	);
	Guards.object<IAuthorizationRemoveAllRolesForSubjectRequest["pathParams"]>(
		ROUTES_SOURCE,
		nameof(request.pathParams),
		request.pathParams
	);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.modelId), request.pathParams.modelId);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.subject), request.pathParams.subject);

	const component = ComponentFactory.get<IAuthorizationComponent>(componentName);
	await component.removeAllRolesForSubject(request.pathParams.modelId, request.pathParams.subject);

	return { statusCode: HttpStatusCode.noContent };
}

/**
 * Perform the get roles for subject operation.
 * @param httpRequestContext The request context for the API.
 * @param componentName The name of the component to use in the routes.
 * @param request The request.
 * @returns The response object with additional http response properties.
 */
export async function authorizationGetRolesForSubject(
	httpRequestContext: IHttpRequestContext,
	componentName: string,
	request: IAuthorizationGetRolesForSubjectRequest
): Promise<IAuthorizationGetRolesForSubjectResponse> {
	Guards.object<IAuthorizationGetRolesForSubjectRequest>(ROUTES_SOURCE, nameof(request), request);
	Guards.object<IAuthorizationGetRolesForSubjectRequest["pathParams"]>(
		ROUTES_SOURCE,
		nameof(request.pathParams),
		request.pathParams
	);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.modelId), request.pathParams.modelId);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.subject), request.pathParams.subject);

	const component = ComponentFactory.get<IAuthorizationComponent>(componentName);
	const roles = await component.getRolesForSubject(
		request.pathParams.modelId,
		request.pathParams.subject
	);

	return { body: { roles } };
}

/**
 * Perform the has role for subject operation.
 * @param httpRequestContext The request context for the API.
 * @param componentName The name of the component to use in the routes.
 * @param request The request.
 * @returns The response object with additional http response properties.
 */
export async function authorizationHasRoleForSubject(
	httpRequestContext: IHttpRequestContext,
	componentName: string,
	request: IAuthorizationHasRoleForSubjectRequest
): Promise<IAuthorizationHasRoleForSubjectResponse> {
	Guards.object<IAuthorizationHasRoleForSubjectRequest>(ROUTES_SOURCE, nameof(request), request);
	Guards.object<IAuthorizationHasRoleForSubjectRequest["pathParams"]>(
		ROUTES_SOURCE,
		nameof(request.pathParams),
		request.pathParams
	);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.modelId), request.pathParams.modelId);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.subject), request.pathParams.subject);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.role), request.pathParams.role);

	const component = ComponentFactory.get<IAuthorizationComponent>(componentName);
	const hasRole = await component.hasRoleForSubject(
		request.pathParams.modelId,
		request.pathParams.subject,
		request.pathParams.role
	);

	return { body: { hasRole } };
}

/**
 * Perform the get subjects for role operation.
 * @param httpRequestContext The request context for the API.
 * @param componentName The name of the component to use in the routes.
 * @param request The request.
 * @returns The response object with additional http response properties.
 */
export async function authorizationGetSubjectsForRole(
	httpRequestContext: IHttpRequestContext,
	componentName: string,
	request: IAuthorizationGetSubjectsForRoleRequest
): Promise<IAuthorizationGetSubjectsForRoleResponse> {
	Guards.object<IAuthorizationGetSubjectsForRoleRequest>(ROUTES_SOURCE, nameof(request), request);
	Guards.object<IAuthorizationGetSubjectsForRoleRequest["pathParams"]>(
		ROUTES_SOURCE,
		nameof(request.pathParams),
		request.pathParams
	);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.modelId), request.pathParams.modelId);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.role), request.pathParams.role);

	const component = ComponentFactory.get<IAuthorizationComponent>(componentName);
	const subjects = await component.getSubjectsForRole(
		request.pathParams.modelId,
		request.pathParams.role
	);

	return { body: { subjects } };
}

/**
 * Perform the add role inheritance operation.
 * @param httpRequestContext The request context for the API.
 * @param componentName The name of the component to use in the routes.
 * @param request The request.
 * @returns The response object with additional http response properties.
 */
export async function authorizationAddRoleInheritance(
	httpRequestContext: IHttpRequestContext,
	componentName: string,
	request: IAuthorizationAddRoleInheritanceRequest
): Promise<INoContentResponse> {
	Guards.object<IAuthorizationAddRoleInheritanceRequest>(ROUTES_SOURCE, nameof(request), request);
	Guards.object<IAuthorizationAddRoleInheritanceRequest["pathParams"]>(
		ROUTES_SOURCE,
		nameof(request.pathParams),
		request.pathParams
	);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.modelId), request.pathParams.modelId);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.role), request.pathParams.role);
	Guards.object<IAuthorizationAddRoleInheritanceRequest["body"]>(
		ROUTES_SOURCE,
		nameof(request.body),
		request.body
	);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.body.inheritsFrom), request.body.inheritsFrom);

	const component = ComponentFactory.get<IAuthorizationComponent>(componentName);
	await component.addRoleInheritance(
		request.pathParams.modelId,
		request.pathParams.role,
		request.body.inheritsFrom
	);

	return { statusCode: HttpStatusCode.noContent };
}

/**
 * Perform the remove role inheritance operation.
 * @param httpRequestContext The request context for the API.
 * @param componentName The name of the component to use in the routes.
 * @param request The request.
 * @returns The response object with additional http response properties.
 */
export async function authorizationRemoveRoleInheritance(
	httpRequestContext: IHttpRequestContext,
	componentName: string,
	request: IAuthorizationRemoveRoleInheritanceRequest
): Promise<INoContentResponse> {
	Guards.object<IAuthorizationRemoveRoleInheritanceRequest>(
		ROUTES_SOURCE,
		nameof(request),
		request
	);
	Guards.object<IAuthorizationRemoveRoleInheritanceRequest["pathParams"]>(
		ROUTES_SOURCE,
		nameof(request.pathParams),
		request.pathParams
	);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.modelId), request.pathParams.modelId);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.role), request.pathParams.role);
	Guards.stringValue(
		ROUTES_SOURCE,
		nameof(request.pathParams.inheritsFrom),
		request.pathParams.inheritsFrom
	);

	const component = ComponentFactory.get<IAuthorizationComponent>(componentName);
	await component.removeRoleInheritance(
		request.pathParams.modelId,
		request.pathParams.role,
		request.pathParams.inheritsFrom
	);

	return { statusCode: HttpStatusCode.noContent };
}

/**
 * Perform the get parent roles operation.
 * @param httpRequestContext The request context for the API.
 * @param componentName The name of the component to use in the routes.
 * @param request The request.
 * @returns The response object with additional http response properties.
 */
export async function authorizationGetParentRoles(
	httpRequestContext: IHttpRequestContext,
	componentName: string,
	request: IAuthorizationGetParentRolesRequest
): Promise<IAuthorizationGetParentRolesResponse> {
	Guards.object<IAuthorizationGetParentRolesRequest>(ROUTES_SOURCE, nameof(request), request);
	Guards.object<IAuthorizationGetParentRolesRequest["pathParams"]>(
		ROUTES_SOURCE,
		nameof(request.pathParams),
		request.pathParams
	);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.modelId), request.pathParams.modelId);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.role), request.pathParams.role);

	const component = ComponentFactory.get<IAuthorizationComponent>(componentName);
	const roles = await component.getParentRoles(request.pathParams.modelId, request.pathParams.role);

	return { body: { roles } };
}

/**
 * Perform the get child roles operation.
 * @param httpRequestContext The request context for the API.
 * @param componentName The name of the component to use in the routes.
 * @param request The request.
 * @returns The response object with additional http response properties.
 */
export async function authorizationGetChildRoles(
	httpRequestContext: IHttpRequestContext,
	componentName: string,
	request: IAuthorizationGetChildRolesRequest
): Promise<IAuthorizationGetChildRolesResponse> {
	Guards.object<IAuthorizationGetChildRolesRequest>(ROUTES_SOURCE, nameof(request), request);
	Guards.object<IAuthorizationGetChildRolesRequest["pathParams"]>(
		ROUTES_SOURCE,
		nameof(request.pathParams),
		request.pathParams
	);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.modelId), request.pathParams.modelId);
	Guards.stringValue(ROUTES_SOURCE, nameof(request.pathParams.role), request.pathParams.role);

	const component = ComponentFactory.get<IAuthorizationComponent>(componentName);
	const roles = await component.getChildRoles(request.pathParams.modelId, request.pathParams.role);

	return { body: { roles } };
}
