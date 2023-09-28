package certificates

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	logger = ctrl.Log.WithName("certificates")
)

// SetupCA make sure that the Root CA and the certificate used by the webhook
// server is created.
//
// In case the Root CA is missing, this function will follow the below steps:
//  1. If the root CA is missing, create it and store certificate and key in a
//     secret
//  2. If the Root CA is created, update the webhooks to use root CA to
//     validate connections
//  3. If root CA is created or webhook server certificate is missing, create a
//     certificate to be used by the webhook server and store
//
// it in a secret
//  4. Wait until the webhooks server certificates are mount in the local
//     filesystem.
//
// It returns an error if something wrong happen in any of the step mentioned
// above
func SetupCA(ctx context.Context, k8sClient client.Client, deploymentsNamespace string, controllerWebhookServiceName string) error {
	if err := setupRootCA(ctx, k8sClient, deploymentsNamespace, controllerWebhookServiceName); err != nil {
		return errors.Join(fmt.Errorf("cannot setup root ca and controller certificate"), err)
	}
	if err := waitForCertificatesFiles("/tmp/k8s-webhook-server/serving-certs/", time.Minute); err != nil {
		return errors.Join(fmt.Errorf("cannot find the controller certificate mounted locally"), err)
	}
	return nil
}

// This function will create and store in secrets, when necessary, the root CA
// and the certificate used in the controller. If the certificate is created,
// the process exit to force kubernetes to redeploy ensuring that the latest
// version of the certificates will be in use
func setupRootCA(ctx context.Context, k8s client.Client, deploymentsNamespace string, controllerWebhookServiceName string) error {
	rootCA, rootCARecreated, err := getOrCreateRootCA(ctx, k8s, deploymentsNamespace)
	if err != nil {
		return err
	}

	err = k8s.Get(ctx, client.ObjectKey{Namespace: deploymentsNamespace, Name: constants.ControllerCertsSecretName}, &corev1.Secret{})
	if err != nil && !apierrors.IsNotFound(err) {
		return errors.Join(fmt.Errorf("cannot get webhooks server certificate secret"), err)
	}
	// we need to update the webhooks server certificate when the root ca change
	// or the certificate is missing, even if the root ca is not new.
	if rootCARecreated || (err != nil && apierrors.IsNotFound(err)) {
		// build the service name used in the certificate
		subjectAlternativeName1 := fmt.Sprintf("%s.%s.svc.cluster.local", controllerWebhookServiceName, deploymentsNamespace)
		subjectAlternativeName2 := fmt.Sprintf("%s.%s.svc", controllerWebhookServiceName, deploymentsNamespace)
		err = renewControllerCerts(ctx, k8s, rootCA, []string{subjectAlternativeName1, subjectAlternativeName2}, deploymentsNamespace)
		if err != nil {
			return err
		}
	}
	return nil
}

func getOrCreateRootCA(ctx context.Context, k8s client.Client, deploymentsNamespace string) (*CA, bool, error) {
	rootCASecret := &corev1.Secret{}
	err := k8s.Get(ctx, client.ObjectKey{Namespace: deploymentsNamespace, Name: constants.RootCASecretName}, rootCASecret)
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, false, errors.Join(fmt.Errorf("cannot get root CA secret"), err)
	}
	rootCARecreate := err != nil && apierrors.IsNotFound(err)
	var rootCA *CA
	if rootCARecreate {
		rootCA, err = createRootCa(ctx, k8s, deploymentsNamespace)
		if err != nil {
			return nil, false, errors.Join(errors.New("unable to create root CA secret"), err)
		}
		logger.Info("root CA secret created")
		certificatePEMEncoded, err := rootCA.PEMEncodeCertificate()
		if err != nil {
			return nil, false, errors.Join(errors.New("unable to PEM encode CA certificate"), err)
		}
		if err := updateWebhooksCaBundle(ctx, k8s, deploymentsNamespace, certificatePEMEncoded.Bytes()); err != nil {
			return nil, false, err
		}
	} else {
		rootCA, err = ExtractCaFromSecret(rootCASecret)
		if err != nil {
			return nil, false, errors.Join(errors.New("unable to extract root CA from secret"), err)
		}
	}
	return rootCA, rootCARecreate, nil
}

// createRootCa generate the root CA certificate and private key and store the
// data in a secret
func createRootCa(ctx context.Context, k8s client.Client, deploymentsNamespace string) (*CA, error) {
	rootCA, err := GenerateCA()
	if err != nil {
		return nil, errors.Join(errors.New("unable to create root ca"), err)
	}
	rootCASecret := &corev1.Secret{
		Type: corev1.SecretTypeTLS,
	}
	certificatePEMEncoded, err := rootCA.PEMEncodeCertificate()
	if err != nil {
		return nil, errors.Join(errors.New("unable to pem encode ca certificate"), err)
	}
	privateKeyPEMEncoded, err := rootCA.PEMEncodePrivateKey()
	if err != nil {
		return nil, errors.Join(errors.New("unable to pem encode ca private key"), err)
	}
	rootCASecret.Data = map[string][]byte{
		corev1.TLSCertKey:       certificatePEMEncoded.Bytes(),
		corev1.TLSPrivateKeyKey: privateKeyPEMEncoded.Bytes(),
	}
	rootCASecret.Name = constants.RootCASecretName
	rootCASecret.Namespace = deploymentsNamespace
	if err := k8s.Create(ctx, rootCASecret); err != nil {
		return nil, errors.Join(errors.New("cannot create root ca secret"), err)
	}
	return rootCA, nil
}

// renewControllerCerts will recreate the webhook server certificate and sing
// it with the given root ca
func renewControllerCerts(ctx context.Context, k8s client.Client, ca *CA, subjectAlternativeNames []string, deploymentsNamespace string) error {
	certificate, certificateKey, err := GenerateCert(ca.CaCertBytes, subjectAlternativeNames, ca.CaPrivateKey)

	if err != nil {
		return fmt.Errorf("unable to create controller certificates")
	}
	controllerCertSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.ControllerCertsSecretName,
			Namespace: deploymentsNamespace,
		},
		Immutable:  new(bool),
		Data:       map[string][]byte{corev1.TLSCertKey: certificate.Bytes(), corev1.TLSPrivateKeyKey: certificateKey.Bytes()},
		StringData: map[string]string{},
		Type:       corev1.SecretTypeTLS,
	}
	err = k8s.Create(ctx, &controllerCertSecret)
	if apierrors.IsAlreadyExists(err) {
		err = k8s.Update(ctx, &controllerCertSecret)
	}
	if err != nil {
		return errors.Join(errors.New("unable to create controller certificate secret"), err)
	}
	logger.Info("webhooks server certificate secret created")
	return nil
}

func updateValidationWebhooks(ctx context.Context, k8s client.Client, namespace string, caBundle []byte) error { //nolint:dupl
	err := retry.OnError(retry.DefaultBackoff, func(err error) bool {
		return apierrors.IsConflict(err) || apierrors.IsNotFound(err)
	}, func() error {
		// Controller webhooks names used here should match what is used in the helm chart installation
		webhookConfig := &admissionregistrationv1.ValidatingWebhookConfiguration{}
		if err := k8s.Get(ctx, client.ObjectKey{Name: constants.ControllerValidatingWebhookName, Namespace: namespace}, webhookConfig); err != nil {
			return errors.Join(fmt.Errorf("cannot get controller validation webhook"), err)
		}
		patchWebhookConfig := webhookConfig.DeepCopy()
		for i := range patchWebhookConfig.Webhooks {
			patchWebhookConfig.Webhooks[i].ClientConfig.CABundle = caBundle
		}
		if err := k8s.Patch(ctx, patchWebhookConfig, client.MergeFrom(webhookConfig)); err != nil {
			return errors.Join(fmt.Errorf("cannot patch the validating webhook: %q ", webhookConfig.Name), err)
		}
		return nil
	})
	if err != nil {
		err = errors.Join(fmt.Errorf("failed to update the validating webhooks"), err)
	}
	return err
}

func updateMutatingWebhooks(ctx context.Context, k8s client.Client, namespace string, caBundle []byte) error { //nolint:dupl
	err := retry.OnError(retry.DefaultBackoff, func(err error) bool {
		return apierrors.IsConflict(err) || apierrors.IsNotFound(err)
	}, func() error {
		mutatingWebhookConfig := &admissionregistrationv1.MutatingWebhookConfiguration{}
		if err := k8s.Get(ctx, client.ObjectKey{Name: constants.ControllerMutatingWebhookName, Namespace: namespace}, mutatingWebhookConfig); err != nil {
			return errors.Join(errors.New("cannot get controller mutating webhooks"), err)
		}
		patchMutatingWebhookConfig := mutatingWebhookConfig.DeepCopy()
		for i := range patchMutatingWebhookConfig.Webhooks {
			patchMutatingWebhookConfig.Webhooks[i].ClientConfig.CABundle = caBundle
		}
		if err := k8s.Patch(ctx, patchMutatingWebhookConfig, client.MergeFrom(mutatingWebhookConfig)); err != nil {
			return errors.Join(fmt.Errorf("cannot patch the mutating webhook: %q ", mutatingWebhookConfig.Name), err)
		}
		return nil
	})
	if err != nil {
		err = errors.Join(fmt.Errorf("failed to update the mutating webhooks"), err)
	}
	return err
}

// updateWebhooksCaBundle updates the webhook configuration to use the given
// caBundle to validate the connections. It updates both validating and
// mutating webhooks
func updateWebhooksCaBundle(ctx context.Context, k8s client.Client, namespace string, caBundle []byte) error {
	logger.Info("update webhook caBundle")
	// Controller webhooks names used here should match what is used in the helm chart installation
	if err := updateValidationWebhooks(ctx, k8s, namespace, caBundle); err != nil {
		return errors.Join(fmt.Errorf("cannot update validation webhooks"), err)
	}

	if err := updateMutatingWebhooks(ctx, k8s, namespace, caBundle); err != nil {
		return errors.Join(fmt.Errorf("cannot update mutating webhooks"), err)
	}

	return nil
}

// checkIfFilesExist checks if all the files given in the arguments exits.
// It return a boolean value to tell if the file exist or not and an error in
// case something wrong happen during the verification process.
func checkIfFilesExist(files ...string) (bool, error) {
	for _, file := range files {
		_, err := os.Stat(file)
		if err == nil {
			logger.Info("file found", "file", file)
			continue
		}
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, errors.Join(fmt.Errorf("failed to get file %s stats", file), err)
	}

	return true, nil
}

// waitForCertificatesFiles waits until kubelet updates the secret mount in the pod or until timout expired.
// It the waiting time exceed the timeout an timeout error is returned
func waitForCertificatesFiles(certificatesDirectory string, timeout time.Duration) error {
	logger.Info("Waiting for certificates files to be mounted", "directory", certificatesDirectory)

	fileWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return errors.Join(fmt.Errorf("cannot create a file watcher"), err)
	}
	defer fileWatcher.Close()

	if err := fileWatcher.Add(certificatesDirectory); err != nil {
		return errors.Join(fmt.Errorf("cannot add the '%s' directory in the file watcher", certificatesDirectory), err)
	}

	// just check before start to wait for fsnotify event. The files may be
	// already there before watcher creation.
	allFilesExist, err := checkIfFilesExist(path.Join(certificatesDirectory, corev1.TLSCertKey), path.Join(certificatesDirectory, corev1.TLSPrivateKeyKey))
	if err != nil {
		return errors.Join(fmt.Errorf("cannot check if certificate files exist"), err)
	}
	if allFilesExist {
		return nil
	}

	return fileWatcherWait(fileWatcher, timeout)
}

func fileWatcherWait(fileWatcher *fsnotify.Watcher, timeout time.Duration) error {
	// A timer is set here to ensure that the process will wait forever.
	// During the tests, it noticeable that kubelet can take some time
	// to update the mount. Even worts, this is configurable by the cluster
	// administrator. Therefore, the controller can waits a long time until
	// the liveness/readiness probes fail and restart the container. Therefore,
	// the probes can be enough to detect this cases. However, to ensure that
	// controller will not stuck here forever if the probes are not properly
	// configured, the timer is used.
	timoutTimer := time.NewTimer(timeout)
	defer timoutTimer.Stop()
	filesFound := []string{}
	for {
		if len(filesFound) == 2 {
			break
		}
		select {
		case <-timoutTimer.C:
			return fmt.Errorf("certificate file watcher timeout")
		case event, ok := <-fileWatcher.Events:
			logger.V(2).Info("watcher event", "event", event, "channel closed", ok)
			if !ok {
				continue
			}
			fileName := path.Base(event.Name)
			if event.Has(fsnotify.Create) {
				if fileName == corev1.TLSCertKey || fileName == corev1.TLSPrivateKeyKey {
					filesFound = append(filesFound, fileName)
					logger.Info("certificate file found", "file", event.Name)
				}
			}
		case err, ok := <-fileWatcher.Errors:
			logger.V(2).Info("error event", "error", err, "channel closed", ok)
			if !ok {
				continue
			}
			return errors.Join(fmt.Errorf("error from the file watcher"), err)
		}
	}
	return nil
}
