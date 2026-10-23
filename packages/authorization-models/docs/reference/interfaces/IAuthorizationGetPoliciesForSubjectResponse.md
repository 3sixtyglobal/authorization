# Interface: IAuthorizationGetPoliciesForSubjectResponse

Response for getting authorization policies for a subject.

## Properties

### body {#body}

> **body**: `object`

The response body.

#### entities

> **entities**: [`IAuthorizationPolicy`](IAuthorizationPolicy.md)[]

The list of policies for the subject.

#### cursor?

> `optional` **cursor?**: `string`

An optional cursor for the next page of results.
