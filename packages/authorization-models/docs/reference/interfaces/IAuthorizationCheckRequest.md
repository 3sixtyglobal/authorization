# Interface: IAuthorizationCheckRequest

Request to check an authorization policy.

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

#### subject

> **subject**: `string`

The subject to check.

#### object

> **object**: `string`

The object to check.

#### action

> **action**: `string`

The action to check.
