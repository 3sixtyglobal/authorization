# Class: AuthorizationService

A service that implements the IAuthorizationComponent interface for handling authorization logic.

## Implements

- `IAuthorizationComponent`

## Constructors

### Constructor

> **new AuthorizationService**(`options?`): `AuthorizationService`

Create a new instance of AuthorizationService.

#### Parameters

##### options?

[`IAuthorizationServiceConstructorOptions`](../interfaces/IAuthorizationServiceConstructorOptions.md)

The constructor options.

#### Returns

`AuthorizationService`

#### Throws

GeneralError If no authorization connectors are registered.

## Properties

### CLASS\_NAME {#class_name}

> `readonly` `static` **CLASS\_NAME**: `string`

Runtime name for the class.

***

### DEFAULT\_AUTHORIZATION\_MODEL\_ID {#default_authorization_model_id}

> `readonly` `static` **DEFAULT\_AUTHORIZATION\_MODEL\_ID**: `string` = `"system"`

The model identifier that is reserved for system-only use.

***

### DEFAULT\_ESCALATED\_PRIVILEGE\_ROLE {#default_escalated_privilege_role}

> `readonly` `static` **DEFAULT\_ESCALATED\_PRIVILEGE\_ROLE**: `string` = `"global-admin"`

The role that bypasses all escalation guards when held by the caller.

## Methods

### className() {#classname}

> **className**(): `string`

Returns the class name of the component.

#### Returns

`string`

The class name of the component.

#### Implementation of

`IAuthorizationComponent.className`

***

### start() {#start}

> **start**(): `Promise`\<`void`\>

Start the service, applying default rules and registering telemetry metrics.

#### Returns

`Promise`\<`void`\>

#### Implementation of

`IAuthorizationComponent.start`

***

### build() {#build}

> **build**(`modelId`, `model`): `Promise`\<`void`\>

Build the authorization model by applying a set of policies and role inheritances.

#### Parameters

##### modelId

`string`

The model identifier selecting which policy set to use.

##### model

`IAuthorizationModel`

The policies and role inheritances to apply.

#### Returns

`Promise`\<`void`\>

Nothing.

#### Implementation of

`IAuthorizationComponent.build`

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

#### Implementation of

`IAuthorizationComponent.check`

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

Nothing.

#### Implementation of

`IAuthorizationComponent.addPolicy`

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

Nothing.

#### Implementation of

`IAuthorizationComponent.removePolicy`

***

### getPoliciesForSubject() {#getpoliciesforsubject}

> **getPoliciesForSubject**(`modelId`, `subject`, `cursor?`, `limit?`): `Promise`\<\{ `entities`: `IAuthorizationPolicy`[]; `cursor?`: `string`; \}\>

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

`Promise`\<\{ `entities`: `IAuthorizationPolicy`[]; `cursor?`: `string`; \}\>

The matching policies and an optional cursor for the next page.

#### Implementation of

`IAuthorizationComponent.getPoliciesForSubject`

***

### getAllPolicies() {#getallpolicies}

> **getAllPolicies**(`modelId`, `subject?`, `cursor?`, `limit?`): `Promise`\<\{ `entities`: `IAuthorizationPolicy`[]; `cursor?`: `string`; \}\>

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

`Promise`\<\{ `entities`: `IAuthorizationPolicy`[]; `cursor?`: `string`; \}\>

The matching policies and an optional cursor for the next page.

#### Implementation of

`IAuthorizationComponent.getAllPolicies`

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

#### Implementation of

`IAuthorizationComponent.getAllRoles`

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

#### Implementation of

`IAuthorizationComponent.hasRoles`

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

Nothing.

#### Implementation of

`IAuthorizationComponent.addRoleForSubject`

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

Nothing.

#### Implementation of

`IAuthorizationComponent.removeRoleForSubject`

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

Nothing.

#### Implementation of

`IAuthorizationComponent.removeAllRolesForSubject`

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

#### Implementation of

`IAuthorizationComponent.getRolesForSubject`

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

#### Implementation of

`IAuthorizationComponent.getSubjectsForRole`

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

#### Implementation of

`IAuthorizationComponent.hasRoleForSubject`

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

Nothing.

#### Implementation of

`IAuthorizationComponent.addRoleInheritance`

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

Nothing.

#### Implementation of

`IAuthorizationComponent.removeRoleInheritance`

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

#### Implementation of

`IAuthorizationComponent.getParentRoles`

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

#### Implementation of

`IAuthorizationComponent.getChildRoles`
