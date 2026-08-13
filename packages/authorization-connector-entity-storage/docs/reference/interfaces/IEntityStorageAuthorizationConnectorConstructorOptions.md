# Interface: IEntityStorageAuthorizationConnectorConstructorOptions

Options for the entity storage authorization connector constructor.

## Properties

### loggingComponentType? {#loggingcomponenttype}

> `optional` **loggingComponentType?**: `string`

The component type for the optional logging.

***

### authorizationPolicyEntityStorageType? {#authorizationpolicyentitystoragetype}

> `optional` **authorizationPolicyEntityStorageType?**: `string`

The entity storage type for authorization policies.

#### Default

```ts
"authorization-policy"
```

***

### authorizationRoleEntityStorageType? {#authorizationroleentitystoragetype}

> `optional` **authorizationRoleEntityStorageType?**: `string`

The entity storage type for authorization role assignments.

#### Default

```ts
"authorization-role"
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

### config? {#config}

> `optional` **config?**: [`IEntityStorageAuthorizationConnectorConfig`](IEntityStorageAuthorizationConnectorConfig.md)

The configuration for the service.
