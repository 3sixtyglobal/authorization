# @3sixty/authorization

This repository provides the building blocks for policy-driven authorisation in TWIN systems, combining shared models, connector implementations, service endpoints, and a client layer that can be composed in different deployment shapes.

Together, these components let teams define access contracts once, apply them through interchangeable connectors, and consume consistent authorisation behaviour from backend services and dependent applications.

## Packages

- [authorization-models](packages/authorization-models/README.md) - Shared interfaces and contract models for authorisation components.
- [authorization-connector-entity-storage](packages/authorization-connector-entity-storage/README.md) - Authorisation connector that resolves access rules from entity storage.
- [authorization-connector-casbin](packages/authorization-connector-casbin/README.md) - Authorisation connector that evaluates policies using Casbin-compatible services.
- [authorization-service](packages/authorization-service/README.md) - Service layer for exposing authorisation operations through HTTP APIs.
- [authorization-rest-client](packages/authorization-rest-client/README.md) - REST client for consuming authorisation service endpoints.

## Contributing

To contribute to this package see the guidelines for building and publishing in [CONTRIBUTING](./CONTRIBUTING.md)

## Origin

This repository is derived from the original [iotaledger/twin-authorization](https://github.com/iotaledger/twin-authorization) repository.
