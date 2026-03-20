# How the audit-scanner works

By default, the audit-scanner starts by auditing all the cluster-wide
resources. Once finished, it scans the namespaced ones.

## Scanning cluster-wide resources

The code gets all the `ClusterAdmissionPolicy` objects defined in the cluster.

> [!NOTE]
>
> `ClusterAdmissionPolicy` is the only type of policy that can target cluster-wide resources (e.g.: `Namespace`, `PersistentVolume`, …).

The code then creates a map with the Kubernetes resource as key, and the
policies targeting that kind of resource as value. This happens
[here](https://github.com/kubewarden/audit-scanner/blob/038da594f989f97420bf235979ae1e60335303e6/internal/policies/client.go#L174).

The map looks like this:

```hcl
{
    { group: "", version: "v1", kind: "Namespace"}: [policy1, policy2],
    { group: "", version: "v1", kind: "PersistentVolume"}: [policy3, policy4],
}
```

`ClusterAdmissionPolicy` policies can also target namespaced resources. Because
of this, the code ignores all the policies that only target namespaced
resources.

The code then starts to iterate over the keys of the map, hence over the types
of cluster-wide Kubernetes resources targeted by the policies. This happens in
the `ScanClusterWideResources` method of `Scanner`. The code gets all the
resources of that type. The resources are fetched with pagination to reduce the
memory usage and the load on the Kubernetes API server.

> [!NOTE]
>
> The order of key iteration isn't deterministic.

The code processes each chunk of resources, and for each resource it invokes
the `auditClusterResource` method of `Scanner`.

> [!IMPORTANT]
> This part of the code is parallelized
>
> For example, assuming the code is auditing the `Namespace` resource kind, and
> there are 20k namespaces in the cluster, the pool of workers evaluates `100`
> namespaces in parallel. The size of the worker pool is configured with the
> `--parallel-resources` flag.

The `auditClusterResource` function takes as input a Kubernetes resource (for
example, a specific `Namespace` object) and all the policies that target that
kind of resource (for example, Kubernetes `Namespace` objects). The code then
iterates over the list of policies and, for each, performs the following
actions:

- Skip the policy if it doesn't target the specific object. This could happen
  because of labels selectors set on the policy.
- Create a fake `CREATE` admission request object for that resource, send it to
  the Policy Server that hosts the policy, and get the response.

> [!IMPORTANT]
>
> This part of the code is parallelized. The number of parallel policies
> evaluated is configured with the `--parallel-policies` flag.

Once all the policies interested in the specific Kubernetes object have been
processed, a `ClusterPolicyReport` object is created. Depending on how the
`audit-scanner` process was started, the `ClusterPolicyReport` object is either
written into `etcd` or printed on the standard output.

## Scanning namespaced resources

The code starts by getting a list of all the `Namespace` objects in the
cluster, except the ones manually excluded by the user. This happens in the
`ScanAllNamespaces` method of `Scanner`.

For each namespace, the code invokes the `ScanNamespace` method.

> [!IMPORTANT]
>
> This part of the code is parallelized. The number of parallel policies to be
> evaluated is configured with the `--parallel-namespaces` flag.

The code uses the `GetPoliciesByNamespace` method to build a map with the
Kubernetes resource as key, and the policies targeting that resource as value.
This map is similar to the one created for the cluster-wide resources. However,
in this case, the types of policies associated with a Kubernetes resource could
be both `ClusterAdmissionPolicy` and `NamespaceAdmissionPolicy`.

The code then iterates over the keys of the map, hence over the types of
namespaced Kubernetes resources targeted by the policies. This is done exactly
like when evaluating the cluster-wide resources. It happens in the
`ScanNamespace` method of `Scanner`.
