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

### timeoutMs? {#timeoutms}

> `optional` **timeoutMs?**: `number`

The request timeout in milliseconds.
