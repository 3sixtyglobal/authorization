# Interface: IAuthorizationGetPoliciesForSubjectRequest

Request to get authorization policies for a subject.

## Properties

### pathParams {#pathparams}

> **pathParams**: `object`

The request path parameters.

#### modelId

> **modelId**: `string`

The model identifier selecting which policy set to use.

#### subject

> **subject**: `string`

The subject to get policies for.

***

### query? {#query}

> `optional` **query?**: `object`

The request query parameters.

#### cursor?

> `optional` **cursor?**: `string`

The cursor to request the next chunk of results.

#### limit?

> `optional` **limit?**: `string`

Limit the number of entities to return.
