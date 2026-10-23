# Interface: IAuthorizationHasRolesRequest

Request to check whether a list of roles exist in the system.

## Properties

### pathParams {#pathparams}

> **pathParams**: `object`

The request path parameters.

#### modelId

> **modelId**: `string`

The model identifier selecting which policy set to use.

***

### body {#body}

> **body**: `object`

The request data.

#### roles

> **roles**: `string`[]

The role names to check.
