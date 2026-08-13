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

The compound identifier for this inheritance relationship, in "role|parentRole" format.

***

### role {#role}

> **role**: `string`

The child role that inherits permissions from the parent.

***

### parentRole {#parentrole}

> **parentRole**: `string`

The parent role whose permissions are inherited.
