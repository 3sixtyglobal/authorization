# Interface: IAuthorizationComponent

Interface describing an authorization component.

## Extends

- `IComponent`

## Methods

### build() {#build}

> **build**(`modelId`, `model`): `Promise`\<`void`\>

Build the authorization model by applying a set of policies and role inheritances.

#### Parameters

##### modelId

`string`

The model identifier selecting which policy set to use.

##### model

[`IAuthorizationModel`](IAuthorizationModel.md)

The policies and role inheritances to apply.

#### Returns

`Promise`\<`void`\>

A promise that resolves when the model has been built.

***

### check() {#check}

> **check**(`modelId`, `subject`, `object`, `action`): `Promise`\<`boolean`\>

Check whether a subject is permitted to perform an action on a resource.

#### Parameters

##### modelId

`string`

The model identifier selecting which policy set to use.

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

> **addPolicy**(`modelId`, `subject`, `object`, `action`): `Promise`\<`void`\>

Add a policy rule.

#### Parameters

##### modelId

`string`

The model identifier selecting which policy set to use.

##### subject

`string`

The subject the policy applies to.

##### object

`string`

The object the policy applies to.

##### action

`string`

The action the policy applies to.

#### Returns

`Promise`\<`void`\>

A promise that resolves when the policy has been added.

***

### removePolicy() {#removepolicy}

> **removePolicy**(`modelId`, `subject`, `object`, `action`): `Promise`\<`void`\>

Remove a policy rule.

#### Parameters

##### modelId

`string`

The model identifier selecting which policy set to use.

##### subject

`string`

The subject of the policy to remove.

##### object

`string`

The object of the policy to remove.

##### action

`string`

The action of the policy to remove.

#### Returns

`Promise`\<`void`\>

A promise that resolves when the policy has been removed.

***

### getPoliciesForSubject() {#getpoliciesforsubject}

> **getPoliciesForSubject**(`modelId`, `subject`, `cursor?`, `limit?`): `Promise`\<\{ `entities`: [`IAuthorizationPolicy`](IAuthorizationPolicy.md)[]; `cursor?`: `string`; \}\>

Get all policy rules for a given subject.

#### Parameters

##### modelId

`string`

The model identifier selecting which policy set to use.

##### subject

`string`

The subject to query.

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

### getAllPolicies() {#getallpolicies}

> **getAllPolicies**(`modelId`, `subject?`, `cursor?`, `limit?`): `Promise`\<\{ `entities`: [`IAuthorizationPolicy`](IAuthorizationPolicy.md)[]; `cursor?`: `string`; \}\>

Get policy rules, optionally filtered by subject.

#### Parameters

##### modelId

`string`

The model identifier selecting which policy set to use.

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

> **getAllRoles**(`modelId`, `cursor?`, `limit?`): `Promise`\<\{ `roles`: `string`[]; `cursor?`: `string`; \}\>

Get all distinct role names in the system.

#### Parameters

##### modelId

`string`

The model identifier selecting which policy set to use.

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

### hasRoles() {#hasroles}

> **hasRoles**(`modelId`, `roles`): `Promise`\<`boolean`[]\>

Check whether each of the given role names exists in the system.

#### Parameters

##### modelId

`string`

The model identifier selecting which policy set to use.

##### roles

`string`[]

The role names to check.

#### Returns

`Promise`\<`boolean`[]\>

An array of booleans in the same order as the input.

***

### addRoleForSubject() {#addroleforsubject}

> **addRoleForSubject**(`modelId`, `subject`, `role`): `Promise`\<`void`\>

Assign a role to a subject.

#### Parameters

##### modelId

`string`

The model identifier selecting which policy set to use.

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

> **removeRoleForSubject**(`modelId`, `subject`, `role`): `Promise`\<`void`\>

Remove a role from a subject.

#### Parameters

##### modelId

`string`

The model identifier selecting which policy set to use.

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

> **removeAllRolesForSubject**(`modelId`, `subject`): `Promise`\<`void`\>

Remove all roles from a subject.

#### Parameters

##### modelId

`string`

The model identifier selecting which policy set to use.

##### subject

`string`

The subject to remove all roles from.

#### Returns

`Promise`\<`void`\>

A promise that resolves when all roles have been removed.

***

### getRolesForSubject() {#getrolesforsubject}

> **getRolesForSubject**(`modelId`, `subject`): `Promise`\<`string`[]\>

Get all roles assigned to a subject.

#### Parameters

##### modelId

`string`

The model identifier selecting which policy set to use.

##### subject

`string`

The subject to query.

#### Returns

`Promise`\<`string`[]\>

The assigned roles.

***

### getSubjectsForRole() {#getsubjectsforrole}

> **getSubjectsForRole**(`modelId`, `role`): `Promise`\<`string`[]\>

Get all subjects assigned to a given role.

#### Parameters

##### modelId

`string`

The model identifier selecting which policy set to use.

##### role

`string`

The role to query.

#### Returns

`Promise`\<`string`[]\>

The subjects with the given role.

***

### hasRoleForSubject() {#hasroleforsubject}

> **hasRoleForSubject**(`modelId`, `subject`, `role`): `Promise`\<`boolean`\>

Check whether a subject has a specific role.

#### Parameters

##### modelId

`string`

The model identifier selecting which policy set to use.

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

> **addRoleInheritance**(`modelId`, `role`, `inheritsFrom`): `Promise`\<`void`\>

Define a parent-child inheritance relationship between two roles.

#### Parameters

##### modelId

`string`

The model identifier selecting which policy set to use.

##### role

`string`

The child role that will inherit permissions from the parent.

##### inheritsFrom

`string`

The parent role whose permissions are inherited.

#### Returns

`Promise`\<`void`\>

A promise that resolves when the role inheritance has been added.

***

### removeRoleInheritance() {#removeroleinheritance}

> **removeRoleInheritance**(`modelId`, `role`, `inheritsFrom`): `Promise`\<`void`\>

Remove a parent-child inheritance relationship between two roles.

#### Parameters

##### modelId

`string`

The model identifier selecting which policy set to use.

##### role

`string`

The child role.

##### inheritsFrom

`string`

The parent role to stop inheriting from.

#### Returns

`Promise`\<`void`\>

A promise that resolves when the role inheritance has been removed.

***

### getParentRoles() {#getparentroles}

> **getParentRoles**(`modelId`, `role`): `Promise`\<`string`[]\>

Get all roles that a given role directly inherits from.

#### Parameters

##### modelId

`string`

The model identifier selecting which policy set to use.

##### role

`string`

The role to query.

#### Returns

`Promise`\<`string`[]\>

The parent roles.

***

### getChildRoles() {#getchildroles}

> **getChildRoles**(`modelId`, `role`): `Promise`\<`string`[]\>

Get all roles that directly inherit from a given role.

#### Parameters

##### modelId

`string`

The model identifier selecting which policy set to use.

##### role

`string`

The role to query.

#### Returns

`Promise`\<`string`[]\>

The child roles.
