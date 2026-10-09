# Casbin Authorization Connector Examples

These examples show how to connect to a Casbin-compatible endpoint, bootstrap connectivity, and perform policy and role operations through the connector API.

## CasbinAuthorizationConnector

```typescript
import { CasbinAuthorizationConnector } from '@3sixty/authorization-connector-casbin';

const connector = new CasbinAuthorizationConnector({
  config: {
    endpoint: 'https://casbin.example.net',
    clientId: 'service-client',
    clientSecret: 'service-secret'
  }
});

console.log(connector.className()); // "CasbinAuthorizationConnector"

const connected = await connector.bootstrap();
console.log(connected); // true
```

```typescript
import { CasbinAuthorizationConnector } from '@3sixty/authorization-connector-casbin';

const connector = new CasbinAuthorizationConnector({
  config: {
    endpoint: 'https://casbin.example.net',
    clientId: 'service-client',
    clientSecret: 'service-secret'
  }
});

await connector.addPolicy('admin', 'reports', 'delete');
await connector.addRoleForSubject('alice', 'admin');

const allowed = await connector.check('alice', 'reports', 'delete');
console.log(allowed); // true

await connector.removePolicy('admin', 'reports', 'delete');
```

```typescript
import { CasbinAuthorizationConnector } from '@3sixty/authorization-connector-casbin';

const connector = new CasbinAuthorizationConnector({
  config: {
    endpoint: 'https://casbin.example.net',
    clientId: 'service-client',
    clientSecret: 'service-secret'
  }
});

await connector.addPolicy('viewer', 'dashboard', 'read');
await connector.addPolicy('viewer', 'dashboard', 'export');

const pageOne = await connector.getAllPolicies('viewer', undefined, 1);
console.log(pageOne.entities); // [{ subject: "viewer", object: "dashboard", action: "read" }]
console.log(pageOne.cursor); // "1"

const pageTwo = await connector.getAllPolicies('viewer', pageOne.cursor, 1);
console.log(pageTwo.entities); // [{ subject: "viewer", object: "dashboard", action: "export" }]

const policiesForViewer = await connector.getPoliciesForSubject('viewer');
console.log(policiesForViewer.entities.length); // 2
```

```typescript
import { CasbinAuthorizationConnector } from '@3sixty/authorization-connector-casbin';

const connector = new CasbinAuthorizationConnector({
  config: {
    endpoint: 'https://casbin.example.net',
    clientId: 'service-client',
    clientSecret: 'service-secret'
  }
});

await connector.addRoleInheritance('editor', 'viewer');
await connector.addRoleForSubject('bob', 'editor');

const roles = await connector.getRolesForSubject('bob');
console.log(roles); // ["editor"]

const subjects = await connector.getSubjectsForRole('editor');
console.log(subjects); // ["bob"]

const hasRole = await connector.hasRoleForSubject('bob', 'editor');
console.log(hasRole); // true

const parentRoles = await connector.getParentRoles('editor');
console.log(parentRoles); // ["viewer"]

const childRoles = await connector.getChildRoles('viewer');
console.log(childRoles); // ["editor"]

const allRoles = await connector.getAllRoles();
console.log(allRoles.roles); // ["editor", "viewer"]

await connector.removeRoleInheritance('editor', 'viewer');
await connector.removeRoleForSubject('bob', 'editor');
await connector.removeAllRolesForSubject('bob');
```
