# Interface: IAuthorizationGetAllPoliciesResponse

Response for getting all authorization policies.

## Properties

### body {#body}

> **body**: `object`

The response body.

#### entities

> **entities**: [`IAuthorizationPolicy`](IAuthorizationPolicy.md)[]

The list of policies.

#### cursor?

> `optional` **cursor?**: `string`

An optional cursor, when defined can be used to retrieve the next chunk of results.
