# Authorization REST Client Examples

These examples demonstrate how to call authorization endpoints through the client API for policy checks, role management, and paginated queries.

## AuthorizationRestClient

```typescript
import { AuthorizationRestClient } from '@twin.org/authorization-rest-client';

const client = new AuthorizationRestClient({
  endpoint: 'https://api.example.net'
});

console.log(client.className()); // "AuthorizationRestClient"
```

```typescript
import { AuthorizationRestClient } from '@twin.org/authorization-rest-client';

const client = new AuthorizationRestClient({
  endpoint: 'https://api.example.net'
});

await client.addPolicy({ subject: 'admin', object: 'reports', action: 'delete' });
await client.addRoleForSubject('alice', 'admin');

const allowed = await client.check('alice', 'reports', 'delete');
console.log(allowed); // true

const hasRole = await client.hasRoleForSubject('alice', 'admin');
console.log(hasRole); // true

await client.removePolicy({ subject: 'admin', object: 'reports', action: 'delete' });
```

```typescript
import { AuthorizationRestClient } from '@twin.org/authorization-rest-client';

const client = new AuthorizationRestClient({
  endpoint: 'https://api.example.net'
});

const firstPage = await client.getAllPolicies('viewer', undefined, 1);
console.log(firstPage.entities); // [{ subject: "viewer", object: "dashboard", action: "read" }]
console.log(firstPage.cursor); // "1"

if (firstPage.cursor !== undefined) {
  const secondPage = await client.getAllPolicies('viewer', firstPage.cursor, 1);
  console.log(secondPage.entities); // [{ subject: "viewer", object: "dashboard", action: "export" }]
}

const policiesForViewer = await client.getPoliciesForSubject('viewer');
console.log(policiesForViewer.length); // 2
```

```typescript
import { AuthorizationRestClient } from '@twin.org/authorization-rest-client';

const client = new AuthorizationRestClient({
  endpoint: 'https://api.example.net'
});

await client.addRoleInheritance('editor', 'viewer');
await client.addRoleForSubject('bob', 'editor');

const rolesForBob = await client.getRolesForSubject('bob');
console.log(rolesForBob); // ["editor"]

const subjectsForEditor = await client.getSubjectsForRole('editor');
console.log(subjectsForEditor); // ["bob"]

const parentRoles = await client.getParentRoles('editor');
console.log(parentRoles); // ["viewer"]

const childRoles = await client.getChildRoles('viewer');
console.log(childRoles); // ["editor"]

const allRoles = await client.getAllRoles();
console.log(allRoles.roles); // ["editor", "viewer"]

await client.removeRoleInheritance('editor', 'viewer');
await client.removeRoleForSubject('bob', 'editor');
await client.removeAllRolesForSubject('bob');
```
