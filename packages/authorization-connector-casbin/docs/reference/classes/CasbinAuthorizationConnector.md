# Class: CasbinAuthorizationConnector

A connector that implements the IAuthorizationConnector interface using the Casbin server REST API.

## Implements

- `IAuthorizationConnector`

## Constructors

### Constructor

> **new CasbinAuthorizationConnector**(`options`): `CasbinAuthorizationConnector`

Creates a new instance of the CasbinAuthorizationConnector.

#### Parameters

##### options

[`ICasbinAuthorizationConnectorConstructorOptions`](../interfaces/ICasbinAuthorizationConnectorConstructorOptions.md)

The options for the connector.

#### Returns

`CasbinAuthorizationConnector`

#### Throws

GeneralError if the enforcer ID is not in owner/name format.

## Properties

### NAMESPACE {#namespace}

> `readonly` `static` **NAMESPACE**: `string` = `"casbin"`

The namespace for the connector.

***

### CLASS\_NAME {#class_name}

> `readonly` `static` **CLASS\_NAME**: `string`

Runtime name for the class.

## Methods

### className() {#classname}

> **className**(): `string`

Returns the class name of the component.

#### Returns

`string`

The class name of the component.

#### Implementation of

`IAuthorizationConnector.className`

***

### bootstrap() {#bootstrap}

> **bootstrap**(`nodeLoggingComponentType?`): `Promise`\<`boolean`\>

Bootstrap the connector and verify connectivity.

#### Parameters

##### nodeLoggingComponentType?

`string`

The node logging component type.

#### Returns

`Promise`\<`boolean`\>

True if the bootstrapping process was successful.

#### Implementation of

`IAuthorizationConnector.bootstrap`

***

### check() {#check}

> **check**(`subject`, `object`, `action`): `Promise`\<`boolean`\>

Check whether a subject is permitted to perform an action on an object.
Evaluates RBAC locally by traversing role inheritance from the stored grouping policies.

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

#### Throws

GeneralError if the check request fails.

#### Implementation of

`IAuthorizationConnector.check`

***

### addPolicy() {#addpolicy}

> **addPolicy**(`policy`): `Promise`\<`void`\>

Add a policy rule.

#### Parameters

##### policy

`IAuthorizationPolicy`

The policy to add.

#### Returns

`Promise`\<`void`\>

Nothing.

#### Throws

GeneralError if the add request fails.

#### Implementation of

`IAuthorizationConnector.addPolicy`

***

### removePolicy() {#removepolicy}

> **removePolicy**(`policy`): `Promise`\<`void`\>

Remove a policy rule.

#### Parameters

##### policy

`IAuthorizationPolicy`

The policy to remove.

#### Returns

`Promise`\<`void`\>

Nothing.

#### Throws

GeneralError if the remove request fails.

#### Implementation of

`IAuthorizationConnector.removePolicy`

***

### getPoliciesForSubject() {#getpoliciesforsubject}

> **getPoliciesForSubject**(`subject`): `Promise`\<`IAuthorizationPolicy`[]\>

Get all policy rules for a given subject.

#### Parameters

##### subject

`string`

The subject to query.

#### Returns

`Promise`\<`IAuthorizationPolicy`[]\>

The matching policies.

#### Throws

GeneralError if the query fails.

#### Implementation of

`IAuthorizationConnector.getPoliciesForSubject`

***

### getAllPolicies() {#getallpolicies}

> **getAllPolicies**(`subject?`, `cursor?`, `limit?`): `Promise`\<\{ `entities`: `IAuthorizationPolicy`[]; `cursor?`: `string`; \}\>

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

`Promise`\<\{ `entities`: `IAuthorizationPolicy`[]; `cursor?`: `string`; \}\>

The matching policies and an optional cursor for the next page.

#### Throws

GeneralError if the query fails.

#### Implementation of

`IAuthorizationConnector.getAllPolicies`

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

#### Throws

GeneralError if the query fails.

#### Implementation of

`IAuthorizationConnector.getAllRoles`

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

Nothing.

#### Throws

GeneralError if the request fails.

#### Implementation of

`IAuthorizationConnector.addRoleForSubject`

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

Nothing.

#### Throws

GeneralError if the request fails.

#### Implementation of

`IAuthorizationConnector.removeRoleForSubject`

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

Nothing.

#### Throws

GeneralError if the request fails.

#### Implementation of

`IAuthorizationConnector.removeAllRolesForSubject`

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

#### Throws

GeneralError if the query fails.

#### Implementation of

`IAuthorizationConnector.getRolesForSubject`

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

#### Throws

GeneralError if the query fails.

#### Implementation of

`IAuthorizationConnector.getSubjectsForRole`

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

#### Throws

GeneralError if the request fails.

#### Implementation of

`IAuthorizationConnector.hasRoleForSubject`

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

Nothing.

#### Throws

GeneralError if the request fails.

#### Implementation of

`IAuthorizationConnector.addRoleInheritance`

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

Nothing.

#### Throws

GeneralError if the request fails.

#### Implementation of

`IAuthorizationConnector.removeRoleInheritance`

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

#### Throws

GeneralError if the query fails.

#### Implementation of

`IAuthorizationConnector.getParentRoles`

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

#### Throws

GeneralError if the query fails.

#### Implementation of

`IAuthorizationConnector.getChildRoles`
