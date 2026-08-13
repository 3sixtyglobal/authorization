# Interface: ICasbinAuthorizationConnectorConfig

Configuration for the Casbin authorization connector.

## Properties

### endpoint {#endpoint}

> **endpoint**: `string`

The base URL of the Casbin server (e.g. "http://localhost:48000").

***

### clientId {#clientid}

> **clientId**: `string`

The OAuth2 client ID for authenticating with the Casbin server API.

***

### clientSecret {#clientsecret}

> **clientSecret**: `string`

The OAuth2 client secret for authenticating with the Casbin server API.

***

### enforcerId {#enforcerid}

> **enforcerId**: `string`

The enforcer identifier in "owner/name" format (e.g. "built-in/built-in").

***

### timeoutMs? {#timeoutms}

> `optional` **timeoutMs?**: `number`

The request timeout in milliseconds.
