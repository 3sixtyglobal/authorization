# Interface: IEntityStorageAuthorizationConnectorConstructorOptions

Options for the entity storage authorization connector constructor.

## Properties

### authorizationPolicyEntityStorageType? {#authorizationpolicyentitystoragetype}

> `optional` **authorizationPolicyEntityStorageType?**: `string`

The entity storage type for authorization policies.

#### Default

```ts
"authorization-policy"
```

***

### authorizationRoleAssignmentEntityStorageType? {#authorizationroleassignmententitystoragetype}

> `optional` **authorizationRoleAssignmentEntityStorageType?**: `string`

The entity storage type for authorization role assignments.

#### Default

```ts
"authorization-role-assignment"
```

***

### authorizationRoleInheritanceEntityStorageType? {#authorizationroleinheritanceentitystoragetype}

> `optional` **authorizationRoleInheritanceEntityStorageType?**: `string`

The entity storage type for authorization role inheritance relationships.

#### Default

```ts
"authorization-role-inheritance"
```

***

### authorizationRoleNameEntityStorageType? {#authorizationrolenameentitystoragetype}

> `optional` **authorizationRoleNameEntityStorageType?**: `string`

The entity storage type for the denormalised role name index.

#### Default

```ts
"authorization-role-name"
```
