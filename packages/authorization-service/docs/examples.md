# Authorization Service Examples

These examples show how to compose policy and role operations behind a single service API and route requests to the configured connector namespace.

## AuthorizationService

```typescript
import { AuthorizationService } from '@twin.org/authorization-service';

const service = new AuthorizationService({
  config: {
    defaultNamespace: 'entity-storage'
  }
});

await service.start();
console.log(service.className()); // "AuthorizationService"
```

```typescript
import { AuthorizationService } from '@twin.org/authorization-service';

const service = new AuthorizationService({
  config: {
    defaultNamespace: 'entity-storage'
  }
});

await service.addPolicy({ subject: 'admin', object: 'reports', action: 'delete' });
await service.addRoleForSubject('alice', 'admin');

const allowed = await service.check('alice', 'reports', 'delete');
console.log(allowed); // true

const hasRole = await service.hasRoleForSubject('alice', 'admin');
console.log(hasRole); // true
```

```typescript
import { AuthorizationService } from '@twin.org/authorization-service';

const service = new AuthorizationService({
  config: {
    defaultNamespace: 'entity-storage'
  }
});

await service.addPolicy({ subject: 'viewer', object: 'dashboard', action: 'read' });
await service.addPolicy({ subject: 'viewer', object: 'dashboard', action: 'export' });

const allPolicies = await service.getAllPolicies('viewer');
console.log(allPolicies.entities.length); // 2

const pagedPolicies = await service.getAllPolicies('viewer', undefined, 1);
console.log(pagedPolicies.entities); // [{ subject: "viewer", object: "dashboard", action: "read" }]
console.log(pagedPolicies.cursor); // "1"

const policiesForSubject = await service.getPoliciesForSubject('viewer');
console.log(policiesForSubject.length); // 2
```

```typescript
import { AuthorizationService } from '@twin.org/authorization-service';

const service = new AuthorizationService({
  config: {
    defaultNamespace: 'entity-storage'
  }
});

await service.addRoleInheritance('editor', 'viewer');
await service.addRoleForSubject('bob', 'editor');

const parentRoles = await service.getParentRoles('editor');
console.log(parentRoles); // ["viewer"]

const childRoles = await service.getChildRoles('viewer');
console.log(childRoles); // ["editor"]

const rolesForBob = await service.getRolesForSubject('bob');
console.log(rolesForBob); // ["editor"]

const subjectsForEditor = await service.getSubjectsForRole('editor');
console.log(subjectsForEditor); // ["bob"]

const allRoles = await service.getAllRoles();
console.log(allRoles.roles); // ["editor", "viewer"]

await service.removeRoleInheritance('editor', 'viewer');
await service.removeRoleForSubject('bob', 'editor');
await service.removeAllRolesForSubject('bob');
await service.removePolicy({ subject: 'viewer', object: 'dashboard', action: 'export' });
```
