# Function: authorizationBuild()

> **authorizationBuild**(`httpRequestContext`, `componentName`, `request`): `Promise`\<`INoContentResponse`\>

Perform the build authorization model operation.

## Parameters

### httpRequestContext

`IHttpRequestContext`

The request context for the API.

### componentName

`string`

The name of the component to use in the routes.

### request

`IAuthorizationBuildRequest`

The request.

## Returns

`Promise`\<`INoContentResponse`\>

The response object with additional http response properties.
