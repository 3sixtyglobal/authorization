# Authorization Packages

## authorization-models

This package defines the shared contracts used by the rest of the authorisation stack. It centralises interfaces and data shapes so connectors, services, and clients can evolve together without diverging semantics.

- [README](../packages/authorization-models/README.md)
- [Examples](../packages/authorization-models/docs/examples.md)
- [Reference](../packages/authorization-models/docs/reference/index.md)
- [Changelog](../packages/authorization-models/docs/changelog.md)

## authorization-connector-entity-storage

This package provides an entity storage-based connector for policy resolution. It is intended for environments where permission and relationship data is sourced from an entity-oriented backing store.

- [README](../packages/authorization-connector-entity-storage/README.md)
- [Examples](../packages/authorization-connector-entity-storage/docs/examples.md)
- [Reference](../packages/authorization-connector-entity-storage/docs/reference/index.md)
- [Changelog](../packages/authorization-connector-entity-storage/docs/changelog.md)

## authorization-connector-casbin

This package integrates Casbin-compatible policy evaluation into the wider authorisation component set. It enables decision checks against externally managed policies while preserving the repository's shared contracts.

- [README](../packages/authorization-connector-casbin/README.md)
- [Examples](../packages/authorization-connector-casbin/docs/examples.md)
- [Reference](../packages/authorization-connector-casbin/docs/reference/index.md)
- [Changelog](../packages/authorization-connector-casbin/docs/changelog.md)

## authorization-service

This package exposes authorisation capabilities through HTTP APIs. It provides the service-side composition point where models and connectors are assembled into deployable endpoints.

- [README](../packages/authorization-service/README.md)
- [Examples](../packages/authorization-service/docs/examples.md)
- [Reference](../packages/authorization-service/docs/reference/index.md)
- [Changelog](../packages/authorization-service/docs/changelog.md)

## authorization-rest-client

This package offers a REST client for consuming the service APIs from other components. It gives callers a consistent integration surface for remote authorisation operations.

- [README](../packages/authorization-rest-client/README.md)
- [Examples](../packages/authorization-rest-client/docs/examples.md)
- [Reference](../packages/authorization-rest-client/docs/reference/index.md)
- [Changelog](../packages/authorization-rest-client/docs/changelog.md)
