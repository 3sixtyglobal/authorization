# @3sixty/authorization-connector-entity-storage

This package provides an entity storage-based connector for authorisation decisions, enabling policy checks against entity and relationship data held in a storage backend.

## Installation

```shell
npm install @3sixty/authorization-connector-entity-storage
```

## Docker

The tests run against both the memory and PostgreSQL entity storage connectors, so they require a running PostgreSQL instance. This is the same instance used by the `@3sixty/entity-storage-connector-postgresql` tests:

```shell
docker pull postgres:latest
docker run -d --name 3sixty-entity-storage-postgresql -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=password -p 5432:5432 postgres:latest
```

The connection settings are read from `tests/.env` and can be overridden locally in `tests/.env.dev`.

## Examples

Usage of the APIs is shown in [docs/examples.md](docs/examples.md)

## Reference

Detailed reference documentation for the API can be found in [docs/reference/index.md](docs/reference/index.md)

## Changelog

The changes between each version can be found in [docs/changelog.md](docs/changelog.md)

## Origin

This package is derived from the original [iotaledger/twin-authorization](https://github.com/iotaledger/twin-authorization/tree/next/packages/authorization-connector-entity-storage) repository.
