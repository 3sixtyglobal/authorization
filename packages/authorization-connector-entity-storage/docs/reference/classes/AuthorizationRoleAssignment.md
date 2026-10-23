# Class: AuthorizationRoleAssignment

Class describing an authorization role assignment entity stored in entity storage.

## Constructors

### Constructor

> **new AuthorizationRoleAssignment**(): `AuthorizationRoleAssignment`

#### Returns

`AuthorizationRoleAssignment`

## Properties

### id {#id}

> **id**: `string`

The compound identifier for this role assignment, in "modelId|subject|role" format.

***

### modelId {#modelid}

> **modelId**: `string`

The model identifier partitioning this assignment.

***

### subject {#subject}

> **subject**: `string`

The subject (user or service) the role is assigned to.

***

### role {#role}

> **role**: `string`

The role assigned to the subject.
