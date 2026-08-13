# Interface: IAuthorizationGetAllRolesResponse

Response for getting all authorization roles.

## Properties

### body {#body}

> **body**: `object`

The response body.

#### roles

> **roles**: `string`[]

The list of role names.

#### cursor?

> `optional` **cursor?**: `string`

An optional cursor, when defined can be used to retrieve the next chunk of results.
