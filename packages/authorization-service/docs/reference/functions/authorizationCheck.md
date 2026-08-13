# Function: authorizationCheck()

> **authorizationCheck**(`httpRequestContext`, `componentName`, `request`): `Promise`\<`IAuthorizationCheckResponse`\>

Perform the check authorization operation.

## Parameters

### httpRequestContext

`IHttpRequestContext`

The request context for the API.

### componentName

`string`

The name of the component to use in the routes.

### request

`IAuthorizationCheckRequest`

The request.

## Returns

`Promise`\<`IAuthorizationCheckResponse`\>

The response object with additional http response properties.
