# Class: AuthorizationRoleInheritance

Class describing an authorization role inheritance entity stored in entity storage.

## Constructors

### Constructor

> **new AuthorizationRoleInheritance**(): `AuthorizationRoleInheritance`

#### Returns

`AuthorizationRoleInheritance`

## Properties

### id {#id}

> **id**: `string`

The compound identifier for this inheritance relationship, in "modelId|role|inheritsFrom" format.

***

### modelId {#modelid}

> **modelId**: `string`

The model identifier partitioning this inheritance.

***

### role {#role}

> **role**: `string`

The child role that inherits permissions from the parent.

***

### inheritsFrom {#inheritsfrom}

> **inheritsFrom**: `string`

The parent role whose permissions are inherited.
