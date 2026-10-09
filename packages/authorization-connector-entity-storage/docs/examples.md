# Entity Storage Authorization Connector Examples

These examples demonstrate how to manage policies, role assignments, and role inheritance rules using entity storage as the backing store.

## EntityStorageAuthorizationConnector

```typescript
import { EntityStorageAuthorizationConnector } from '@3sixty/authorization-connector-entity-storage';

const connector = new EntityStorageAuthorizationConnector();
console.log(connector.className()); // "EntityStorageAuthorizationConnector"

await connector.addPolicy({
  subject: 'admin',
  object: 'reports',
  action: 'delete'
});

await connector.addRoleForSubject('alice', 'admin');

const canDelete = await connector.check('alice', 'reports', 'delete');
console.log(canDelete); // true

await connector.removePolicy({
  subject: 'admin',
  object: 'reports',
  action: 'delete'
});
```

```typescript
import { EntityStorageAuthorizationConnector } from '@3sixty/authorization-connector-entity-storage';

const connector = new EntityStorageAuthorizationConnector();

await connector.addRoleInheritance('editor', 'viewer');
await connector.addRoleForSubject('bob', 'editor');

const parentRoles = await connector.getParentRoles('editor');
console.log(parentRoles); // ["viewer"]

const childRoles = await connector.getChildRoles('viewer');
console.log(childRoles); // ["editor"]
```

```typescript
import { EntityStorageAuthorizationConnector } from '@3sixty/authorization-connector-entity-storage';

const connector = new EntityStorageAuthorizationConnector();

await connector.addPolicy({ subject: 'viewer', object: 'dashboard', action: 'read' });
await connector.addPolicy({ subject: 'viewer', object: 'dashboard', action: 'export' });

const firstPage = await connector.getAllPolicies('viewer', undefined, 1);
console.log(firstPage.entities); // [{ subject: "viewer", object: "dashboard", action: "read" }]
console.log(firstPage.cursor); // "1"

const secondPage = await connector.getAllPolicies('viewer', firstPage.cursor, 1);
console.log(secondPage.entities); // [{ subject: "viewer", object: "dashboard", action: "export" }]
console.log(secondPage.cursor); // undefined

const policiesForViewer = await connector.getPoliciesForSubject('viewer');
console.log(policiesForViewer.length); // 2
```

```typescript
import { EntityStorageAuthorizationConnector } from '@3sixty/authorization-connector-entity-storage';

const connector = new EntityStorageAuthorizationConnector();

await connector.addRoleForSubject('carol', 'reviewer');
await connector.addRoleForSubject('carol', 'publisher');

const roles = await connector.getRolesForSubject('carol');
console.log(roles); // ["reviewer", "publisher"]

const subjects = await connector.getSubjectsForRole('reviewer');
console.log(subjects); // ["carol"]

const hasRole = await connector.hasRoleForSubject('carol', 'publisher');
console.log(hasRole); // true

const allRoles = await connector.getAllRoles();
console.log(allRoles.roles); // ["publisher", "reviewer"]

await connector.removeRoleForSubject('carol', 'publisher');
await connector.removeAllRolesForSubject('carol');
```
