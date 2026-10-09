# @3sixty/authorization-connector-casbin

This package provides a Casbin-compatible connector for authorisation policy evaluation, allowing decision checks to be delegated to policy services while keeping a consistent contract with the rest of the repository.

## Installation

```shell
npm install @3sixty/authorization-connector-casbin
```

## Docker

The integration tests require a running instance of the `casbin/casdoor-all-in-one` Docker image:

```shell
docker run -d -p 48000:8000 --name 3sixty-authorization-casbin casbin/casdoor-all-in-one
```

## Examples

Usage of the APIs is shown in [docs/examples.md](docs/examples.md)

## Reference

Detailed reference documentation for the API can be found in [docs/reference/index.md](docs/reference/index.md)

## Changelog

The changes between each version can be found in [docs/changelog.md](docs/changelog.md)

## Origin

This package is derived from the original [iotaledger/twin-authorization](https://github.com/iotaledger/twin-authorization/tree/next/packages/authorization-connector-casbin) repository.
