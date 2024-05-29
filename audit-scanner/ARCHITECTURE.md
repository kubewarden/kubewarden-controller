## How the audit-scanner works

By default, the audit-scanner starts by auditing all the cluster-wide resources.
Once this is done, it scans the namespaced ones.

### Scanning cluster-wide resources

The code gets all the `ClusterAdmissionPolicy` objects defined inside of the cluster.

> Note: `ClusterAdmissionPolicy` is the only type of policy that can target cluster-wide resources (e.g.: `Namespace`, `PersistentVolume`, …).

The code then creates a map with the Kubernetes resource as key, and the policies targeting that kind of resource as value.
This is done [here](https://github.com/kubewarden/audit-scanner/blob/038da594f989f97420bf235979ae1e60335303e6/internal/policies/client.go#L174).

The map would look like this:

```hcl
{
    { group: "", version: "v1", kind: "Namespace"}: [policy1, policy2],
    { group: "", version: "v1", kind: "PersistentVolume"}: [policy3, policy4],
}
```

`ClusterAdmissionPolicy` policies can target also namespaced resources. Because of that, the code will ignore all the policies that target only
namespaced resources.

The code then starts to iterate over the keys of the map, hence over the types of cluster-wide Kubernetes resources that are targeted by the policies. This is done
[here](https://github.com/kubewarden/audit-scanner/blob/038da594f989f97420bf235979ae1e60335303e6/internal/scanner/scanner.go#L223).
The code will get all the resources of that type. The resources are fetched with pagination to reduce the memory usage and the load on the Kuberentes API server.

> Note: the order by which the keys are iterated is not deterministic.

The code processes each chunk of resources, and for each resource it invokes the [`auditClusterResource`](https://github.com/kubewarden/audit-scanner/blob/038da594f989f97420bf235979ae1e60335303e6/internal/scanner/scanner.go#L246)
method.

> **Important:** this portion of the code is parallelized
>
> For example, assuming the code is auditing the `Namespace` resource kind, and there are 20k namespaces in the cluster,
> the pool of workers will evaluate `100` namespaces in parallel. The size of the worker pool is currently hard coded to
> [`here`](https://github.com/kubewarden/audit-scanner/blob/038da594f989f97420bf235979ae1e60335303e6/internal/scanner/scanner.go#L32).

The [`auditClusterResource`](https://github.com/kubewarden/audit-scanner/blob/038da594f989f97420bf235979ae1e60335303e6/internal/scanner/scanner.go#L325) function
takes as input a Kubernetes resource (e.g.: a specific `Namespace` object) and all the policies that target that kind of resource (e.g.: kubernetes `Namespace` objects).
The code then iterates over the list of policies and, for each one performs the following actions:

- Skip the policy if it doesn't target the specific object. This could happen because of labels selectors set on the policy
- Create a fake `CREATE` admission request object for that resource, send it to the Policy Server that hosts the policy, and get the response

> **Note:** this part of the code is not concurrent. Each policy is evaulated sequentially, one at a time. This is something that could be improved in the future.

Once all the policies interested about the specific Kubernetes object have been processed, a `ClusterPolicyReport` object is created.
Depending on how the `audit-scanner` process was started, the `ClusterPolicyReport` object is either written into etcd or is printed on the standard output.

### Scanning namespaced resources

The code starts by getting a list of all the `Namespace` objects in the cluster, except the ones manually excluded by the user.
See [here](https://github.com/kubewarden/audit-scanner/blob/038da594f989f97420bf235979ae1e60335303e6/internal/scanner/scanner.go#L183).

For each namespace, the code invokes the [`ScanNamespace`](https://github.com/kubewarden/audit-scanner/blob/038da594f989f97420bf235979ae1e60335303e6/internal/scanner/scanner.go#L120)
method.

> **Note:** this part of the code is not concurrent. Each Namespace is evaluated sequentially. This is something that could be improved in the future.

The code uses the [`GetPoliciesForANamespace`](https://github.com/kubewarden/audit-scanner/blob/038da594f989f97420bf235979ae1e60335303e6/internal/policies/client.go#L61) method
to build a map with the Kubernetes resource as key, and the policies targeting that resource as value.
This map is similar to the one created for the cluster-wide resources. However, in this case the types of policies associated with a Kubernetes
resource could be both `ClusterAdmissionPolicy` and `NamespaceAdmissionPolicy`.

The code then iterates over the keys of the map, hence over the types of namespaced Kubernetes resources that are targeted by the policies. This is done exactly like
with when evaluating the cluster-wide resources. See [here](https://github.com/kubewarden/audit-scanner/blob/038da594f989f97420bf235979ae1e60335303e6/internal/scanner/scanner.go#L140-L170).
