# Interface: IAuthorizationAddRoleInheritanceRequest

Request to add a role inheritance.

## Properties

### pathParams {#pathparams}

> **pathParams**: `object`

The request path parameters.

#### modelId

> **modelId**: `string`

The model identifier selecting which policy set to use.

#### role

> **role**: `string`

The role to add the inheritance to.

***

### body {#body}

> **body**: `object`

The request data.

#### inheritsFrom

> **inheritsFrom**: `string`

The parent role to inherit from.
