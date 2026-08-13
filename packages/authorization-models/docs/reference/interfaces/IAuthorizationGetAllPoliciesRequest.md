# Interface: IAuthorizationGetAllPoliciesRequest

Request to get all authorization policies.

## Properties

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
