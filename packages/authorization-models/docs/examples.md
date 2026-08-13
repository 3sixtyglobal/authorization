# Authorization Models Examples

These examples show how to work with policy and role contracts in a type-safe way and how to resolve connector implementations through the shared factory.

## AuthorizationConnectorFactory

```typescript
import { AuthorizationConnectorFactory } from '@twin.org/authorization-models';

const connectorNames = AuthorizationConnectorFactory.names();
console.log(connectorNames); // ["entity-storage", "casbin"]

const connector = AuthorizationConnectorFactory.get('entity-storage');
console.log(connector.className()); // "EntityStorageAuthorizationConnector"
```

## IAuthorizationPolicy

```typescript
import type { IAuthorizationPolicy } from '@twin.org/authorization-models';

const readPolicy: IAuthorizationPolicy = {
  subject: 'editor',
  object: 'documents',
  action: 'read'
};

const writePolicy: IAuthorizationPolicy = {
  subject: 'editor',
  object: 'documents',
  action: 'write'
};

console.log(readPolicy); // { subject: "editor", object: "documents", action: "read" }
console.log(writePolicy); // { subject: "editor", object: "documents", action: "write" }
```

## IAuthorizationComponent

```typescript
import type { IAuthorizationComponent } from '@twin.org/authorization-models';

async function configureAndCheck(component: IAuthorizationComponent): Promise<void> {
  await component.addPolicy({
    subject: 'admin',
    object: 'reports',
    action: 'delete'
  });

  await component.addRoleForSubject('alice', 'admin');

  const allowed = await component.check('alice', 'reports', 'delete');
  console.log(allowed); // true

  const roles = await component.getRolesForSubject('alice');
  console.log(roles); // ["admin"]
}
```
