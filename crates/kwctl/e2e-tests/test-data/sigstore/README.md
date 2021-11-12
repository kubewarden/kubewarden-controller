# Sigstore artifacts

This folder contains artifacts such as signing keys, used for testing
[Sigstore](www.sigstore.dev) functionality.

## Verifying

Verification tests are performed by signing with
[cosign](https://github.com/sigstore/cosign), and verifying with `kwctl`.

### Recreating the image under test

Obtain the same image under test, under our control:
```console
$ kwctl pull registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.9
$ kwctl push \
   ~/.cache/kubewarden/store/registry/ghcr.io/kubewarden/policies/pod-privileged:v0.1.9 \
   ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
```

Sign it with 2 keys, key1 with 2 annotations, key2 with 1 annotation. Key3 is
not used to sign this image (signing it pushes new images with the metadata,
which will be triangulated back to our image):

```console
$ COSIGN_PASSWORD=kubewarden cosign generate-key-pair
$ mv cosign.key cosign1.key; mv cosign.pub cosign1.pub
$ COSIGN_PASSWORD=kubewarden cosign sign \
  -key cosign1.key -a env=prod -a stable=true \
  ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
$ COSIGN_PASSWORD=kubewarden cosign generate-key-pair
$ mv cosign.key cosign2.key; mv cosign.pub cosign2.pub
$ COSIGN_PASSWORD=kubewarden  cosign sign \
  -key cosign2.key -a env=prod \
  ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
```
