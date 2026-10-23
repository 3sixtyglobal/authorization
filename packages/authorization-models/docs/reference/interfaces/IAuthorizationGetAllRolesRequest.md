# Interface: IAuthorizationGetAllRolesRequest

Request to get all authorization roles.

## Properties

### pathParams {#pathparams}

> **pathParams**: `object`

The request path parameters.

#### modelId

> **modelId**: `string`

The model identifier selecting which policy set to use.

***

### query? {#query}

> `optional` **query?**: `object`

The optional query parameters.

#### cursor?

> `optional` **cursor?**: `string`

The cursor to request the next chunk of results.

#### limit?

> `optional` **limit?**: `string`

Limit the number of roles to return.
