# Interface: IAuthorizationRemoveRoleInheritanceRequest

Request to remove a role inheritance.

## Properties

### pathParams {#pathparams}

> **pathParams**: `object`

The request path parameters.

#### modelId

> **modelId**: `string`

The model identifier selecting which policy set to use.

#### role

> **role**: `string`

The role to remove the inheritance from.

#### inheritsFrom

> **inheritsFrom**: `string`

The parent role to remove.
