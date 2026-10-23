# Interface: IAuthorizationGetAllPoliciesRequest

Request to get all authorization policies.

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

#### subject?

> `optional` **subject?**: `string`

Filter policies by subject.

#### cursor?

> `optional` **cursor?**: `string`

The cursor to request the next chunk of results.

#### limit?

> `optional` **limit?**: `string`

Limit the number of entities to return.
