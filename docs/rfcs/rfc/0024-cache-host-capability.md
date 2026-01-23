|              |                                           |
| :----------- | :---------------------------------------- |
| Feature Name | Cache Host Capability                     |
| Start Date   | 2025-09-25                                |
| Category     | host-capabilities                         |
| RFC PR       | https://github.com/kubewarden/rfc/pull/52 |
| State        | **ACCEPTED**                              |

# Summary

This RFC proposes adding a new host capability that allows policy authors to
store and retrieve arbitrary data in a configurable cache. This will grant
authors more control over caching logic, helping to speed up policy evaluations
and reduce load on external services.

# Motivation

Some users complain that the default cache Time To Live (TTL) in the current
Kubewarden implementation (60 seconds) is too short for their needs. This
forces policies to contact external services too often, causing an excessive
number of requests. Since the current cache implementation does not allow for
customization, this proposal introduces a new host capability that gives policy
authors direct control over a dedicated cache backend.

Initially, this cache will be an in-process memory store. However, the design
must consider the future addition of other cache backends, such as Redis. This
would enable more advanced use cases, like sharing cached data among different
policy-server instances.

## Examples / User Stories

- As a policy author, I want a host capability that allows me to store and
  retrieve arbitrary data from a cache, so that I can skip redundant calls to
  external services and speed up policy evaluations.
- As a policy author, I want to control the lifespan (Time To Live, or TTL) of
  the data I store in the cache.
- As a Kubewarden maintainer, I want the new host capability to be extensible,
  allowing for the future addition of other cache backends (e.g., Redis) without
  a major redesign.

# Detailed design

Implementing the new cache host capability requires changes to the
`policy-server` and `policy-evaluator` code bases.

The `policy-evaluator` will gain a new `callback_handler` to perform cache
operations. This handler will expose `set` and `get` operations for writing to
and reading from the cache, respectively.

The `policy-server` will be responsible for instantiating the cache backend and
passing it to the evaluation environment. The initial implementation will use a
default in-memory cache, so no new CLI flags are needed yet. In the future, as
new backends are added, configuration flags will be introduced to select and
configure the desired backend.

## Host Capability Request Specification

The `cache` host capability will include two operations:

- `kubewarden.cache.set`: Stores a value in the cache.
- `kubewarden.cache.get`: Retrieves a value from the cache.

### `kubewarden.cache.set`

The request payload to set a value will be:

```json
{
  "key": "some-unique-string-key",
  "value": [10, 20, 30, 40, 50],
  "ttl": 600
}
```

- `key` (string): The unique identifier for the data being stored.
- `value` (byte array): The arbitrary data to be stored in the cache.
- `ttl` (integer): The lifespan of the data in seconds. After this time
  expires, the data will be evicted from the cache.

The response payload will be:

```json
{
  "code": 0,
  "message": "Operation successful"
}
```

- `code` (integer): The status code of the operation. A value of `0` indicates
  success. Any non-zero value indicates an error.
- `message` (string): A descriptive message, especially useful when `code` is
  non-zero.

### `kubewarden.cache.get`

The request payload to retrieve a value will be:

```json
{
  "key": "some-unique-string-key"
}
```

- `key` (string): The key of the data to retrieve.

The response payload will be:

```json
{
  "code": 0,
  "message": "Value found",
  "value": [10, 20, 30, 40, 50]
}
```

- `code` (integer): The status code of the operation. `0` indicates success.
- `message` (string): A descriptive message.
- `value` (byte array): If the key exists and has not expired, this
  field will contain the stored data.

It is important to note that a cache miss (due to an expired or non-existent
key) is not considered an error. In this scenario, the response will have a
`code` of `0`, but the `value` field will be empty.

## SDKs Changes

All official Kubewarden SDKs (`rust`, `go`, `js`, etc.) must be updated. They
should provide language-native functions and types that abstract away the raw
JSON payload construction and host calls for the `cache.get` and `cache.set`
operations.

## Suggested technical details

This section is detailed suggestion of how to implement this host capability.

### policy-evaluator Changes

1. A new callback handler module will be added under `src/callback_handler`
   containing the functions to perform the `set` and `get` cache operations.
2. The `CallbackHandler` struct and its builder (`CallbackHandlerBuilder`) will
   be updated with a new `cache` field. This allows `policy-server` to inject
   the active cache backend into the handler.
3. The `CallbackRequestType` enum will be extended to include variants for the
   new cache operations (`CacheSet` and `CacheGet`).
4. The `handle_request` function in `CallbackHandler` will add two new match
   arms to route these new request types to the appropriate cache operation
   functions.
5. Existing host capabilities that currently use their own caching (via the
   `cached` macro) must be refactored to use this new shared cache backend.
   This consolidates caching logic into a single mechanism.
6. To prevent key collisions between internal Kubewarden caches and
   policy-defined caches, a reserved prefix (e.g., `kubewarden_internal_`) must
   be used for all keys set by host capabilities. The `cache.set` operation must
   reject any policy-provided key that uses this reserved prefix.
7. The `cache` field in `CallbackHandler` will be a trait object (e.g.,
   `Box<dyn Cache>`) to support multiple backend implementations at runtime.
   The `cached` crate's traits can serve as a foundation for this contract.

### policy-server Changes

The `policy-server` will be responsible for instantiating the cache backend and
passing it to the `CallbackHandlerBuilder`. The `new_from_config` function will
be modified to create the appropriate cache backend based on runtime
configuration. If no backend is specified, it will default to the in-memory
cache provided by the `cached` crate. The default cache backend from cached
crate should be `ExpiringValueCache`. It's a in memory cache that allow
defining ttl for each value individually.

For in-memory cache, it's also necessary to start a Tokio task to clean expired
items in memory. Otherwise, we can leave expired items in memory forever if
they are not get in future calls.

Even using `cached` crate as the library manage the cache. The interaction with
it should be abstract by some types under control of the Kubewarden team.
Therefore, if necessary to move away of the dependency, the under the hood
library can be changed with mimimal change in the application logic. This also
allow the team adding another backend that is not nativaly supported by the
`cached` crate. The goal is just to no couple Kubewarden code too much to the
`cached` crate.

# Drawbacks

# Alternatives

The following alternatices descriptions are related to the suggested
implementation.

To avoid the performance overhead of runtime polymorphism (`dyn Trait`), we
could define the cache backend at compile time using generics. However, this is
not feasible for our use case, as the desired cache backend must be
configurable at runtime based on user-provided settings.

Considered not rely on `cached` crate. Even the crate seems to be used by a
good number or person. Its repository looks missing some good practices like
proper tagging and documentation could be better. However, writing the cache
from scratch does not sound worth now. Furthermore, the crate is already in use
by the project, the first iteration should continue to use it. But adding a
abstraction layer on top of it. Just to make replacement and extension using
other libraries easier in the future.

# Unresolved questions

# References

https://docs.rs/cached/latest/cached/index.html
https://docs.rs/cached/latest/cached/stores/struct.ExpiringValueCache.html#method.flush
