# Interface: IAuthorizationAddRoleForSubjectRequest

Request to add a role for a subject.

## Properties

### pathParams {#pathparams}

> **pathParams**: `object`

The request path parameters.

#### modelId

> **modelId**: `string`

The model identifier selecting which policy set to use.

#### subject

> **subject**: `string`

The subject to add the role to.

***

### body {#body}

> **body**: `object`

The request data.

#### role

> **role**: `string`

The role to add.
