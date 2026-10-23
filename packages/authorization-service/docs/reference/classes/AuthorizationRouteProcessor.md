# Class: AuthorizationRouteProcessor

Use the identity from the context ids to check their authorization for a route.

## Implements

- `IBaseRouteProcessor`

## Constructors

### Constructor

> **new AuthorizationRouteProcessor**(`options?`): `AuthorizationRouteProcessor`

Create a new instance of AuthorizationRouteProcessor.

#### Parameters

##### options?

[`IAuthorizationRouteProcessorConstructorOptions`](../interfaces/IAuthorizationRouteProcessorConstructorOptions.md)

Options for the processor.

#### Returns

`AuthorizationRouteProcessor`

## Properties

### CLASS\_NAME {#class_name}

> `readonly` `static` **CLASS\_NAME**: `string`

Runtime name for the class.

***

### DEFAULT\_AUTHORIZATION\_MODEL\_ID {#default_authorization_model_id}

> `readonly` `static` **DEFAULT\_AUTHORIZATION\_MODEL\_ID**: `string` = `"system"`

The model identifier that is reserved for system-only use.

## Methods

### className() {#classname}

> **className**(): `string`

Returns the class name of the component.

#### Returns

`string`

The class name of the component.

#### Implementation of

`IBaseRouteProcessor.className`

***

### pre() {#pre}

> **pre**(`request`, `response`, `route`, `contextIds`, `processorState`): `Promise`\<`void`\>

Pre process the REST request for the specified route.

#### Parameters

##### request

`IHttpServerRequest`

The incoming request.

##### response

`IHttpResponse`

The outgoing response.

##### route

`IBaseRoute` \| `undefined`

The route to process.

##### contextIds

`IContextIds`

The context IDs of the request.

##### processorState

\{\[`id`: `string`\]: `unknown`; \}

The state handed through the processors.

#### Returns

`Promise`\<`void`\>

A promise that resolves when the JWT has been verified and the context populated, or an error response set.

#### Implementation of

`IBaseRouteProcessor.pre`
