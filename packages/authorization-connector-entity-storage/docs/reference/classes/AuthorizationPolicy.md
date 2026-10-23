# Class: AuthorizationPolicy

Class describing an authorization policy entity stored in entity storage.

## Constructors

### Constructor

> **new AuthorizationPolicy**(): `AuthorizationPolicy`

#### Returns

`AuthorizationPolicy`

## Properties

### id {#id}

> **id**: `string`

The compound identifier for this policy rule, in "modelId|subject|object|action" format.

***

### modelId {#modelid}

> **modelId**: `string`

The model identifier partitioning this policy.

***

### subject {#subject}

> **subject**: `string`

The subject (user, service, or role) the policy applies to.

***

### object {#object}

> **object**: `string`

The object the authorization policy applies to.

***

### action {#action}

> **action**: `string`

The action the authorization policy allows.
