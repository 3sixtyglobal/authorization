# Interface: IAuthorizationServiceConfig

Configuration for the Authorization Service.

## Properties

### defaultNamespace? {#defaultnamespace}

> `optional` **defaultNamespace?**: `string`

The default connector namespace to use for authorization; defaults to the first registered connector.

***

### checkCacheCapacity? {#checkcachecapacity}

> `optional` **checkCacheCapacity?**: `number`

Maximum number of check results to hold in the cache

#### Default

```ts
1000.
```

***

### checkCacheTtiMs? {#checkcachettims}

> `optional` **checkCacheTtiMs?**: `number`

Time-to-idle in milliseconds for cached check results.

#### Default

```ts
60000.
```

***

### authorizationModelId? {#authorizationmodelid}

> `optional` **authorizationModelId?**: `string`

The model identifier that is reserved for system-only use.

#### Default

```ts
system
```

***

### escalatedPrivilegeRole? {#escalatedprivilegerole}

> `optional` **escalatedPrivilegeRole?**: `string`

The role that bypasses all escalation guards when held by the caller.

#### Default

```ts
global-admin
```
