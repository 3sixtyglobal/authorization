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

`check` returns `true` if the user holds any role that transitively grants the required permission, and `false` otherwise. The object must be a leaf-level permission name (such as a route's `operationId`); checking against a role or intermediate permission name is not supported and always returns `false`.

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

## Tenant and organization scoping

Rules can be scoped along two independent dimensions, both resolved from the ambient context ids rather than passed as parameters, so the `IAuthorizationConnector` / `IAuthorizationComponent` method signatures are unchanged.

**Tenant** separation is a storage concern. The entity storage connector delegates it to the entity storage layer: partition the configured storage by the tenant context id (`partitionContextIds: [ContextIdKeys.Tenant]`) and each tenant gets a fully isolated policy set. The Casbin connector provisions a dedicated enforcer and policy table per tenant. In both cases two tenants can never see each other's rules.

**Organization** scoping rides on the rules themselves, inside a tenant. The organization is resolved as `ContextIdKeys.UserOrganization`, falling back to `ContextIdKeys.Organization` (the same convention other TWIN services use). The rules are:

- **Writes stamp the current organization.** `addPolicy`, `addRoleForSubject`, and `addRoleInheritance` called with an organization context create organization-scoped rules; called without one they create global rules, exactly as before.
- **Checks and queries match global rules plus the current organization's rules.** A global rule is visible in every organization; an organization-scoped rule is visible only when the ambient organization matches. Without an organization context only global rules apply, so one organization's rules can never influence another's decisions, or global ones.
- **Removals target the current organization exactly.** Removing a rule under an organization context removes only that organization's rule; a global rule can only be removed from a global context.

Role names are a single namespace per model: `getAllRoles` and `hasRoles` report names across all organizations, while assignments, inheritance, and policies are scoped.

### Migrating from global to organization-specific rules

Because global rules stay visible in every organization, a deployment can start global and move to organization-specific rules later without changing any `check` call sites:

1. For each organization, re-create the rule under that organization's context (`addPolicy` / `addRoleForSubject` / `addRoleInheritance` with the organization context id set).
2. Remove the global rule from a global context.

Behaviour is identical before and after the migration; organizations can then diverge independently. Note that rules are allow-only: a global rule cannot be overridden per organization, so step 2 is required before an organization's copy can be meaningfully revoked.
