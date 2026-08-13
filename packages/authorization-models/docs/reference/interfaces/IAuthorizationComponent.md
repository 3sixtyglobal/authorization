# Interface: IAuthorizationComponent

Interface describing an authorization component.

## Extends

- `IComponent`

## Methods

### check() {#check}

> **check**(`subject`, `object`, `action`): `Promise`\<`boolean`\>

Check whether a subject is permitted to perform an action on a resource.

#### Parameters

##### subject

`string`

The subject requesting access.

##### object

`string`

The object being accessed.

##### action

`string`

The action to check.

#### Returns

`Promise`\<`boolean`\>

True if access is granted, false otherwise.

***

### addPolicy() {#addpolicy}

> **addPolicy**(`policy`): `Promise`\<`void`\>

Add a policy rule.

#### Parameters

##### policy

[`IAuthorizationPolicy`](IAuthorizationPolicy.md)

The policy to add.

#### Returns

`Promise`\<`void`\>

A promise that resolves when the policy has been added.

***

### removePolicy() {#removepolicy}

> **removePolicy**(`policy`): `Promise`\<`void`\>

Remove a policy rule.

#### Parameters

##### policy

[`IAuthorizationPolicy`](IAuthorizationPolicy.md)

The policy to remove.

#### Returns

`Promise`\<`void`\>

A promise that resolves when the policy has been removed.

***

### getPoliciesForSubject() {#getpoliciesforsubject}

> **getPoliciesForSubject**(`subject`): `Promise`\<[`IAuthorizationPolicy`](IAuthorizationPolicy.md)[]\>

Get all policy rules for a given subject.

#### Parameters

##### subject

`string`

The subject to query.

#### Returns

`Promise`\<[`IAuthorizationPolicy`](IAuthorizationPolicy.md)[]\>

The matching policies.

***

### getAllPolicies() {#getallpolicies}

> **getAllPolicies**(`subject?`, `cursor?`, `limit?`): `Promise`\<\{ `entities`: [`IAuthorizationPolicy`](IAuthorizationPolicy.md)[]; `cursor?`: `string`; \}\>

Get policy rules, optionally filtered by subject.

#### Parameters

##### subject?

`string`

Optional subject to filter by.

##### cursor?

`string`

The cursor to request the next chunk of results.

##### limit?

`number`

Limit the number of entities to return.

#### Returns

`Promise`\<\{ `entities`: [`IAuthorizationPolicy`](IAuthorizationPolicy.md)[]; `cursor?`: `string`; \}\>

The matching policies and an optional cursor for the next page.

***

### getAllRoles() {#getallroles}

> **getAllRoles**(`cursor?`, `limit?`): `Promise`\<\{ `roles`: `string`[]; `cursor?`: `string`; \}\>

Get all distinct role names in the system.

#### Parameters

##### cursor?

`string`

The cursor to request the next chunk of results.

##### limit?

`number`

Limit the number of roles to return.

#### Returns

`Promise`\<\{ `roles`: `string`[]; `cursor?`: `string`; \}\>

The role names and an optional cursor for the next page.

***

### addRoleForSubject() {#addroleforsubject}

> **addRoleForSubject**(`subject`, `role`): `Promise`\<`void`\>

Assign a role to a subject.

#### Parameters

##### subject

`string`

The subject to assign the role to.

##### role

`string`

The role to assign.

#### Returns

`Promise`\<`void`\>

A promise that resolves when the role has been assigned.

***

### removeRoleForSubject() {#removeroleforsubject}

> **removeRoleForSubject**(`subject`, `role`): `Promise`\<`void`\>

Remove a role from a subject.

#### Parameters

##### subject

`string`

The subject to remove the role from.

##### role

`string`

The role to remove.

#### Returns

`Promise`\<`void`\>

A promise that resolves when the role has been removed.

***

### removeAllRolesForSubject() {#removeallrolesforsubject}

> **removeAllRolesForSubject**(`subject`): `Promise`\<`void`\>

Remove all roles from a subject.

#### Parameters

##### subject

`string`

The subject to remove all roles from.

#### Returns

`Promise`\<`void`\>

A promise that resolves when all roles have been removed.

***

### getRolesForSubject() {#getrolesforsubject}

> **getRolesForSubject**(`subject`): `Promise`\<`string`[]\>

Get all roles assigned to a subject.

#### Parameters

##### subject

`string`

The subject to query.

#### Returns

`Promise`\<`string`[]\>

The assigned roles.

***

### getSubjectsForRole() {#getsubjectsforrole}

> **getSubjectsForRole**(`role`): `Promise`\<`string`[]\>

Get all subjects assigned to a given role.

#### Parameters

##### role

`string`

The role to query.

#### Returns

`Promise`\<`string`[]\>

The subjects with the given role.

***

### hasRoleForSubject() {#hasroleforsubject}

> **hasRoleForSubject**(`subject`, `role`): `Promise`\<`boolean`\>

Check whether a subject has a specific role.

#### Parameters

##### subject

`string`

The subject to check.

##### role

`string`

The role to check for.

#### Returns

`Promise`\<`boolean`\>

True if the subject has the role.

***

### addRoleInheritance() {#addroleinheritance}

> **addRoleInheritance**(`role`, `parentRole`): `Promise`\<`void`\>

Define a parent-child inheritance relationship between two roles.

#### Parameters

##### role

`string`

The child role that will inherit permissions from the parent.

##### parentRole

`string`

The parent role whose permissions are inherited.

#### Returns

`Promise`\<`void`\>

A promise that resolves when the role inheritance has been added.

***

### removeRoleInheritance() {#removeroleinheritance}

> **removeRoleInheritance**(`role`, `parentRole`): `Promise`\<`void`\>

Remove a parent-child inheritance relationship between two roles.

#### Parameters

##### role

`string`

The child role.

##### parentRole

`string`

The parent role to stop inheriting from.

#### Returns

`Promise`\<`void`\>

A promise that resolves when the role inheritance has been removed.

***

### getParentRoles() {#getparentroles}

> **getParentRoles**(`role`): `Promise`\<`string`[]\>

Get all roles that a given role directly inherits from.

#### Parameters

##### role

`string`

The role to query.

#### Returns

`Promise`\<`string`[]\>

The parent roles.

***

### getChildRoles() {#getchildroles}

> **getChildRoles**(`role`): `Promise`\<`string`[]\>

Get all roles that directly inherit from a given role.

#### Parameters

##### role

`string`

The role to query.

#### Returns

`Promise`\<`string`[]\>

The child roles.
