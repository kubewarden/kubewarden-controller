|              |                                                   |
| :----------- | :------------------------------------------------ |
| Feature Name | Reflectors database cache                         |
| Start Date   | Mar 26 2024                                       |
| Category     | enhancement,feature                               |
| RFC PR       | [PR33](https://github.com/kubewarden/rfc/pull/33) |
| State        | **ACCEPTED**                                      |

# Summary

[summary]: #summary

This RFC proposes to offload the reflectors cache to a disk-based database to free up memory in the policy server.

# Motivation

[motivation]: #motivation

Reflectors are a key component of the policy evaluator context-aware capabilities.
They are used to keep track of the state of the Kubernetes cluster and to cache objects fetched from the Kubernetes API server that are needed to evaluate those policies that require information about the cluster state.

The reflectors cache is currently stored in memory, which can lead to high memory usage in the policy server.

The purpose of this RFC is to introduce a database into the reflectors to offload the cache to disk.
Also, by using a database, we can implement queries that will reduce the number of reflectors that are created and maintained in memory.

## Examples / User Stories

[examples]: #examples

- As a user, I want to reduce the memory usage of the policy server when caching objects from the Kubernetes API server.

# Detailed design

[design]: #detailed-design

A [reflector](https://docs.rs/kube/latest/kube/runtime/reflector/fn.reflector.html) is a component that watches for changes in the Kubernetes API server and caches the objects that are relevant to the policy evaluation.
It stores the watched objects in memory, and it is responsible for keeping them up-to-date.
It also offers a reader interface to query the objects stored in the cache.
At the time of writing, the reflectors are used to speed up the evaluation of policies that require information about the Kubernetes cluster state,
by avoiding fetching the same objects from the Kubernetes API server multiple times during the evaluation of a single request.
However, the reflectors cache is currently stored in memory, which can lead to high memory usage in the policy server.
According to the [kube-rs ](https://kube.rs/controllers/optimization/#reflector-optimization)optimization[ guide](https://kube.rs/controllers/optimization/#reflector-optimization) and the [reflector documentation](https://docs.rs/kube/latest/kube/runtime/reflector/fn.reflector.html#memory-usage), the cache [Store](https://docs.rs/kube-runtime/0.88.1/src/kube_runtime/reflector/store.rs.html#13) is the main source of memory usage and it is directly proportional to how many objects are stored.
In the worst-case scenario (Pods with many sidecar containers and many environment variables), the reflectors cache can consume up to 1GB of memory for ~2000 objects.
It's possible to reduce memory usage by dropping objects managed fields, however, this is still not enough in large clusters.
Every time a `fieldSelector` or a `labelSelector` is used, a new reflector is created, which increases the memory usage by possibly duplicating the objects in memory.
Also adding more reflectors can increase the load on the Kubernetes API server since they rely on Kubernetes API server watches.

At the time of writing, reflectors are created lazily the first time they are needed.

The current flow is as follows:

1. The policy server receives a request to evaluate a policy.
2. The policy server creates a new reflector for each resource kind that is being requested by the policy.
3. The reflector fetches the objects from the Kubernetes API server and stores them in memory, this step is triggered by the event `watcher::Event::Restarted`.
4. The policy server evaluates the policy using the objects stored in the reflectors cache. If the reflector is not ready yet, the policy request blocks until the cache is built.
5. The reflector keeps the objects up-to-date by watching for changes in the Kubernetes API server.

## SQLite database store

This RFC proposes to create a custom `Store` that uses a disk-based database to store the objects.
The database will be used to store the objects in JSON format, and it will be queried using the `fieldSelector` and `labelSelector` to reduce the number of reflectors that are created and maintained in memory.
SQLite is a good candidate for the database, as it is a single-file database and supports SQL and JSON queries.
Also, the database can be considered ephemeral, as the reflectors can be recreated from the Kubernetes API server if needed.
The database will contain a table for each resource kind that is being watched by the reflectors.
The table name will be in the following format: 'group_version_kind'.
For example, the table name for the `Pod` resource kind will be `v1_pods` and the table name for the `Deployment` resource kind will be `apps_v1_deployments`.

As SQLite does not support concurrent writes, the database will be accessed by a single writer thread and multiple reader threads.
This could change in the future once `BEGIN CONCURRENT` will be supported.
For the time being, if we hit concurrency issues, we could consider using a single database per resource type.

Table schema:

| Column    | Data Type    | Constraints |
| --------- | ------------ | ----------- |
| name      | VARCHAR(253) | NOT NULL    |
| namespace | VARCHAR(253) |             |
| object    | JSON         | NOT NULL    |

Primary Key: (name, namespace)

Since we need to create a database when the policy server starts, we need to ensure that the database and the tables are created before the reflectors are started.
For this reason, the reflectors will be created at boot time instead of being created lazily.

The new flow will be as follows:

1. The policy server starts.
2. The policy server creates the database and the connection pool.
3. The policy server iterates over the resource kinds that are being set in the policy configuration and creates the tables and the reflectors.
4. The reflector receives a `watcher::Event::Restarted` event and fetches the objects from the Kubernetes API server and stores them in the database.
5. The reflector keeps the objects up-to-date by watching for changes in the Kubernetes API server, receiving the events `watcher::Event::Added`, `watcher::Event::Modified` and `watcher::Event::Deleted`.
6. When a policy requests a resource or a list of resources, the policy server queries the database and returns the objects to the policy callback channel.

## Querying the database

The host callback handler will be modified to query the database and return the objects to the policy callback channel.

Get the pod named `nginx` in the `default` namespace:

```sql
SELECT object FROM v1_pods WHERE name = 'nginx' AND namespace = 'default';
```

Get all the pods in the `default` namespace:

```sql
SELECT object FROM v1_pods WHERE namespace = 'default';
```

Get all the pods with the label `app=nginx`:

```sql
SELECT object FROM v1_pods WHERE json_extract(object, '$.metadata.labels.app') = 'nginx';
```

## Gatekeeper inventory cache

Gatekeeper policies require a different approach, as they expect the cache data to be present under the `data.inventory` document.
To learn more about the Gatekeeper inventory document, please refer to the [Gatekeeper documentation](https://open-policy-agent.github.io/gatekeeper/website/docs/sync/#accessing-replicated-data).

At the time of writing, we store the serialized inventory in memory to speed up the evaluation of Gatekeeper policies.
Even though this solves the problem of having to wait for the inventory to be built and serialized at policy evaluation time from the resource-based reflectors,
it can lead to high memory usage in the policy server especially in large clusters.

This RFC proposes to create a dedicated table in the database to store the inventory cache.
The inventory is built at boot time and kept up-to-date by watching for changes in the Kubernetes API server.

# Drawbacks

[drawbacks]: #drawbacks

At boot time the policy server will start the reflectors.
Once a reflector is started it will receive a `watcher::Event::Restarted` event with all the objects of the resource kind it is watching.
Even if the request is paginated (see: https://docs.rs/kube/latest/kube/runtime/watcher/struct.Config.html#method.page_size)
to reduce Kubernetes API and serialization load, the items will be buffered up in the watcher event causing a spike in memory usage.

To mitigate this, we could start the reflectors sequentially or in batches.

# Alternatives

As an alternative, we could consider keeping the lazy creation of reflectors.
Also, it could be possible to use a merge strategy which could work as follows:

1. Policy `policy1` requests a list of pods in the `production` namespace.
2. The reflector is created and fetches the objects from the Kubernetes API server, storing them in the database.
3. Policy `policy2` requests a list of pods in the `development` namespace.
4. A new reflector is created, watching pods in both `production` and `development` namespaces.

This way we could reduce the number of items that are requested from the Kubernetes API server and stored in the database.

# Unresolved questions

[unresolved]: #unresolved-questions
