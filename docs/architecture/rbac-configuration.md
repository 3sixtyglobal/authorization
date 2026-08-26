# RBAC Configuration

The authorization system uses Role-Based Access Control (RBAC). Operations are protected by named permissions; roles are identities that inherit permissions; users are assigned roles. A check at call time asks: does this user hold a role that grants the required permission for this operation?

## Core concepts

**Permission**: a named capability string such as `tenant:read` or `tenant:write`. Each protected operation is associated with the permission required to call it.

**Role**: a named identity assigned to a user. Roles gain capabilities by inheriting permissions or other roles.

**Inheritance**: permissions and roles share the same inheritance graph. Declaring that `tenant:write` inherits from `tenant:read` means any subject holding `tenant:write` automatically satisfies `tenant:read` checks. Role-to-role inheritance works the same way, so a super-role transitively gains every capability of its children.

**Model**: a named partition of policies, roles, and inheritance relationships. Every method accepts a `modelId` as its first argument. This lets one authorization service serve multiple independent policy sets simultaneously, for example one model for REST API routes and another for internal trade workflows. Subjects, policies, and role graphs in different models are fully isolated from each other.

## Example: tenant and user management

The following example defines two independent permission domains (tenant management and user management) and a single `global-admin` role that spans both. All calls use a model identifier of `"rest"` to target the REST API policy set.

### Route permissions

Tenant routes are each associated with either `tenant:read` for queries or `tenant:write` for mutations:

| `operationId`  | Method | Path           | Permission     |
| -------------- | ------ | -------------- | -------------- |
| `tenantGet`    | GET    | `/tenants/:id` | `tenant:read`  |
| `tenantList`   | GET    | `/tenants`     | `tenant:read`  |
| `tenantCreate` | POST   | `/tenants`     | `tenant:write` |
| `tenantDelete` | DELETE | `/tenants/:id` | `tenant:write` |

User management routes follow the same pattern with a separate permission domain:

| `operationId` | Method | Path         | Permission   |
| ------------- | ------ | ------------ | ------------ |
| `userGet`     | GET    | `/users/:id` | `user:read`  |
| `userList`    | GET    | `/users`     | `user:read`  |
| `userCreate`  | POST   | `/users`     | `user:write` |
| `userDelete`  | DELETE | `/users/:id` | `user:write` |

### Registering policies

Each `operationId` and permission pairing is registered as a policy. The `action` is always `"execute"`:

```typescript
await authorizationComponent.addPolicy('rest', 'tenant:read', 'tenantGet', 'execute');
await authorizationComponent.addPolicy('rest', 'tenant:read', 'tenantList', 'execute');
await authorizationComponent.addPolicy('rest', 'tenant:write', 'tenantCreate', 'execute');
await authorizationComponent.addPolicy('rest', 'tenant:write', 'tenantDelete', 'execute');

await authorizationComponent.addPolicy('rest', 'user:read', 'userGet', 'execute');
await authorizationComponent.addPolicy('rest', 'user:read', 'userList', 'execute');
await authorizationComponent.addPolicy('rest', 'user:write', 'userCreate', 'execute');
await authorizationComponent.addPolicy('rest', 'user:write', 'userDelete', 'execute');
```

### Role hierarchy

The hierarchy defines three roles. `tenant-admin` governs the tenant domain, `user-admin` governs the user domain, and `global-admin` inherits from both:

```text
global-admin
├── tenant-admin
│   └── tenant:write          (tenantCreate · tenantDelete)
│       └── tenant:read       (tenantGet · tenantList)
└── user-admin
    └── user:write            (userCreate · userDelete)
        └── user:read         (userGet · userList)
```

Because `tenant:write` inherits from `tenant:read`, a subject holding `tenant:write` can execute all tenant operations regardless of which permission each route individually requires. The same principle applies in the user domain.

### Inheritance setup

Configure the inheritance relationships once at application startup:

```typescript
// Permission inheritance: write subsumes read in each domain
await authorizationComponent.addRoleInheritance('rest', 'tenant:write', 'tenant:read');
await authorizationComponent.addRoleInheritance('rest', 'user:write', 'user:read');

// Role-to-permission links: each domain role grants its write permission
await authorizationComponent.addRoleInheritance('rest', 'tenant-admin', 'tenant:write');
await authorizationComponent.addRoleInheritance('rest', 'user-admin', 'user:write');

// Role-to-role inheritance: global-admin spans both domains
await authorizationComponent.addRoleInheritance('rest', 'global-admin', 'tenant-admin');
await authorizationComponent.addRoleInheritance('rest', 'global-admin', 'user-admin');
```

The order of these calls does not matter; the system evaluates the full graph at check time.

### Assigning roles to users

Roles are assigned per subject (typically a user identifier):

```typescript
await authorizationComponent.addRoleForSubject('rest', 'alice', 'tenant-admin');
await authorizationComponent.addRoleForSubject('rest', 'bob', 'global-admin');
```

`alice` can perform any tenant operation. `bob` can perform any tenant or user operation because `global-admin` transitively inherits the capabilities of both domain roles.

### Checking access

To verify whether a user can execute a specific operation, call `check` with the model identifier, the user identifier as `subject`, the `operationId` as `object`, and `"execute"` as the action:

```typescript
const allowed = await authorizationComponent.check('rest', userId, operationId, 'execute');
```

`check` returns `true` if the user holds any role that transitively grants the required permission, and `false` otherwise.

Because the inheritance graph is traversed recursively, `check` works correctly regardless of which node in the hierarchy the `object` resolves to. You can check against any node in the graph, from a high-level role name down to a specific leaf permission, and the result is consistent with the full traversal from the subject.

**Checking a leaf node (specific permission):** the policy `addPolicy('rest', 'tenant:read', 'tenantGet', 'execute')` records that the `tenant:read` permission grants `tenantGet`. When a user assigned `tenant-admin` calls `check('rest', userId, 'tenantGet', 'execute')`, the system walks the inheritance graph outward from the subject until it finds a node that holds a direct policy for `tenantGet`. It finds it via `tenant-admin` → `tenant:write` → `tenant:read`.

**Checking an entry node (role or permission name):** because permissions are nodes in the same graph, you can also check at a higher level. `check('rest', userId, 'tenant:read', 'execute')` asks whether the user holds anything that grants the `tenant:read` permission itself. A subject assigned `tenant-admin` passes because the inheritance chain reaches `tenant:read` directly. This lets you guard coarser-grained gates, such as confirming a user holds any tenant management capability before loading a shared resource.

In practice the `AuthorizationProcessor` always checks at the leaf level by using the route's `operationId` as the object. Application code that needs a broader gate can check at any node by supplying a role or permission name instead.

### Access matrix

Access is evaluated transitively through the inheritance chain:

| Operation      | `tenant-admin` | `user-admin` | `global-admin` |
| -------------- | :------------: | :----------: | :------------: |
| `tenantGet`    |       ✓        |              |       ✓        |
| `tenantList`   |       ✓        |              |       ✓        |
| `tenantCreate` |       ✓        |              |       ✓        |
| `tenantDelete` |       ✓        |              |       ✓        |
| `userGet`      |                |      ✓       |       ✓        |
| `userList`     |                |      ✓       |       ✓        |
| `userCreate`   |                |      ✓       |       ✓        |
| `userDelete`   |                |      ✓       |       ✓        |
