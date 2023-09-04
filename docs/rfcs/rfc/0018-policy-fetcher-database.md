|              |                                                   |
| :----------- | :------------------------------------------------ |
| Feature Name | policy-fetcher database store                     |
| Start Date   | 01/09/2023                                        |
| Category     | enhancement,feature                               |
| RFC PR       | [PR26](https://github.com/kubewarden/rfc/pull/26) |
| State        | **ACCEPTED**                                      |

# Summary

[summary]: #summary

This RFC proposes to add a database to the policy-fetcher.

# Motivation

Docker, podman and others use a key-value store to keep track of the container images (and layers) being downloaded.
Initially, this route was not followed because we wanted to keep the `policy-fetcher` as simple as possible.

The current approach requires the utilization of a specific directory structure for storing the downloaded policies.
This structure enables us to track the URI from which each policy was obtained.
However, this presents certain drawbacks, especially on specific filesystems like Windows, where we are required to encode the path to base64.
This encoding is necessary to avoid encountering filesystem limitations, including restrictions related to forbidden characters in the path.
Furthermore, it prevents us from tracking whether the same policy was downloaded from different URIs.

The purpose of this RFC is to introduce a database into the policy-fetcher to enable the tracking of downloaded policies and their associated URIs.
This approach offers several advantages:

- Data deduplication: Policies are not as big as container images, but this could save disk space in certain circumstances.
- No need to sanitize protocol, host, path to policy and policy name (+ version). Everything would be saved using its shasum.

## Examples / User Stories

[examples]: #examples

As a user, I want to be able to track the policies that have been downloaded and their associated URIs.

As a user, I want to retrieve a policy from the store by its shasum or URI.

As a user, I want to be able to migrate the old directory-based store to the new database-based store.

# Detailed design

[design]: #detailed-design

Given the following policies:

| policy name                                         | shasum  |
| --------------------------------------------------- | ------- |
| ghcr.io/kubewarden/privileged-policy:0.1.0          | foobar1 |
| ghcr.io/kubewarden/privileged-policy:0.1.1          | foobar2 |
| registry.local.lan/policies/privileged-policy:0.1.1 | foobar2 |

They would be stored in a flat directory structure as follows:

```
~/.cache/kubewarden/store/
├── foobar1
└── foobar2
└── policies.db

```

A potential candidate for the database is sqlite.
It is battle-tested and allows multiple processes to access the database concurrently (see [here](https://www.sqlite.org/faq.html#q5)).
This would be an improvement over the current implementation, which is not safe for concurrent access to the store.
It is possible to compile sqlite client library statically, which is a requirement for the `kwctl` and `policy-server` binaries.

Additional refactoring and cleanup might be needed to allow testing of the database and filesystem access in isolation.

## Migration and backward compatibility

A migration path from the old directory-based store to the new database-based store should be provided.
This should happen automatically when the store is instantiated if the database does not exist, ensuring backward compatibility.

The migration path should be as follows:

1. When the store is instantiated, if the database does not exist, trigger the migration.
2. Create a temporary store path.
3. For each policy in the old store:

- Compute the sha of the policy wasm file.
- Write the wasm file to the new store directory as `<sha>.wasm`.

1. If there are errors during the migration, the migration should be aborted and the old store should be kept. By using `tempfile` we can ensure that the temporary store path is removed when the migration is aborted.
2. Rename the old store path to ".bkp" and copy the new store to the store path.
3. Finally, remove the old store path.

This change does not involve `policy-server`, since it currently
uses an ephemeral store when running inside of Kubernetes, hence policies are always downloaded at startup time.

# Drawbacks

[drawbacks]: #drawbacks

The platform-dependant code cannot be removed completely, since the migration path requires it.
We could consider removing it in a future (major) release.

# Alternatives

[alternatives]: #alternatives

We could consider using a different database, but sqlite is a strong candidate.

# Unresolved questions

[unresolved]: #unresolved-questions

---
