package reconcilers

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"time"

	opsterv1 "github.com/Opster/opensearch-k8s-operator/opensearch-operator/api/v1"
	"github.com/Opster/opensearch-k8s-operator/opensearch-operator/pkg/builders"
	"github.com/Opster/opensearch-k8s-operator/opensearch-operator/pkg/helpers"
	"github.com/Opster/opensearch-k8s-operator/opensearch-operator/pkg/reconcilers/k8s"
	"github.com/cisco-open/operator-tools/pkg/reconciler"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	checksumAnnotation = "securityconfig/checksum"

	adminCert = "/certs/tls.crt"
	adminKey  = "/certs/tls.key"
	caCert    = "/certs/ca.crt"

	SecurityAdminBaseCmdTmpl = `ADMIN=/usr/share/opensearch/plugins/opensearch-security/tools/securityadmin.sh;
chmod +x $ADMIN;
until curl -k --silent https://%s:%v;
do
echo 'Waiting to connect to the cluster'; sleep 120;
done;`

	// CRITEO - Add --explicit-replicas 0-2 to force .opendistro_security index to be created with auto-expand mode enabled, up to 2 replicas
	ApplyAllYmlCmdTmpl = `count=0;
until $ADMIN -cacert %s -cert %s -key %s -cd %s --explicit-replicas 0-2 -icl -nhnv -h %s -p %v || (( count++ >= 20 ));
do
sleep 20;
done;`

	// CRITEO - Add --explicit-replicas 0-2 to force .opendistro_security index to be created with auto-expand mode enabled, up to 2 replicas
	ApplySingleYmlCmdTmpl = `count=0;
until $ADMIN -cacert %s -cert %s -key %s -f %s -t %s --explicit-replicas 0-2 -icl -nhnv -h %s -p %v || (( count++ >= 20 ));
do
sleep 20;
done;`
)

var ymlToFileType = map[string]string{
	"internal_users.yml": "internalusers",
	"roles.yml":          "roles",
	"roles_mapping.yml":  "rolesmapping",
	"action_groups.yml":  "actiongroups",
	"tenants.yml":        "tenants",
	"nodes_dn.yml":       "nodesdn",
	"whitelist.yml":      "whitelist",
	"audit.yml":          "audit",
	"allowlist.yml":      "allowlist",
	"config.yml":         "config",
}

type SecurityconfigReconciler struct {
	client            k8s.K8sClient
	recorder          record.EventRecorder
	reconcilerContext *ReconcilerContext
	instance          *opsterv1.OpenSearchCluster
	logger            logr.Logger
}

func NewSecurityconfigReconciler(
	client client.Client,
	ctx context.Context,
	recorder record.EventRecorder,
	reconcilerContext *ReconcilerContext,
	instance *opsterv1.OpenSearchCluster,
	opts ...reconciler.ResourceReconcilerOption,
) *SecurityconfigReconciler {
	return &SecurityconfigReconciler{
		client:            k8s.NewK8sClient(client, ctx, append(opts, reconciler.WithLog(log.FromContext(ctx).WithValues("reconciler", "securityconfig")))...),
		reconcilerContext: reconcilerContext,
		recorder:          recorder,
		instance:          instance,
		logger:            log.FromContext(ctx),
	}
}

func (r *SecurityconfigReconciler) Reconcile() (ctrl.Result, error) {
	if r.instance.Spec.Security == nil {
		return ctrl.Result{}, nil
	}
	annotations := map[string]string{"cluster-name": r.instance.GetName()}

	var configSecretName string
	var checksumval string
	var cmdArg string

	adminCertName := r.determineAdminSecret()
	namespace := r.instance.Namespace
	clusterName := r.instance.Name
	jobName := clusterName + "-securityconfig-update"

	if adminCertName == "" {
		r.logger.Info("Cluster is running with demo certificates.")
		r.recorder.AnnotatedEventf(r.instance, annotations, "Warning", "Security", "Notice - Cluster is running with demo certificates")
		return ctrl.Result{}, nil
	}

	// Checking if Security Config values are empty and creates a default-securityconfig secret
	if r.instance.Spec.Security.Config != nil && r.instance.Spec.Security.Config.SecurityconfigSecret.Name != "" {
		// Use a user passed value of SecurityconfigSecret name
		configSecretName = r.instance.Spec.Security.Config.SecurityconfigSecret.Name
		// Wait for secret to be available
		configSecret, err := r.client.GetSecret(configSecretName, namespace)
		if err != nil {
			if apierrors.IsNotFound(err) {
				r.logger.Info(fmt.Sprintf("Waiting for secret '%s' that contains the securityconfig to be created", configSecretName))
				r.recorder.AnnotatedEventf(r.instance, annotations, "Warning", "Security", "Notice - Waiting for secret '%s' that contains the securityconfig to be created", configSecretName)
				return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 10}, nil
			}
			return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 10}, err
		}

		// Calculate checksum and check for changes
		var checksumerr error
		checksumval, checksumerr = checksum(configSecret.Data)
		if checksumerr != nil {
			return ctrl.Result{}, checksumerr
		}
		if err := r.securityconfigSubpaths(r.instance, &configSecret); err != nil {
			return ctrl.Result{}, err
		}
		cmdArg = BuildCmdArg(r.instance, &configSecret, r.logger)
	} else {
		r.logger.Info("Not passed any SecurityconfigSecret")
	}

	job, err := r.client.GetJob(jobName, namespace)
	if err == nil {
		value, exists := job.Annotations[checksumAnnotation]
		if exists && value == checksumval {
			// Nothing to do, current securityconfig already applied
			return ctrl.Result{}, nil
		}
		// Delete old job
		r.logger.Info("Deleting old update job")
		err := r.client.DeleteJob(&job)
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	// If the cluster has not yet initialized or
	// securityconfig secret was not passed, build the command to apply all yml files
	if !r.instance.Status.Initialized || len(cmdArg) == 0 {
		clusterHostName := BuildClusterSvcHostName(r.instance)
		httpPort, securityConfigPort, securityconfigPath := helpers.VersionCheck(r.instance)
		cmdArg = fmt.Sprintf(SecurityAdminBaseCmdTmpl, clusterHostName, httpPort) +
			fmt.Sprintf(ApplyAllYmlCmdTmpl, caCert, adminCert, adminKey, securityconfigPath, clusterHostName, securityConfigPort)
	}

	endpointCASecretName, err := r.resolveEndpointCASecret(namespace, adminCertName, annotations)
	if err != nil {
		if apierrors.IsNotFound(err) {
			r.logger.Info(fmt.Sprintf("Waiting for secret that contains the endpoint CA certificate: %v", err))
			r.recorder.AnnotatedEventf(r.instance, annotations, "Warning", "Security", "Waiting for secret that contains the endpoint CA certificate: %v", err)
			return ctrl.Result{RequeueAfter: time.Second * 10}, nil
		}
		if errors.Is(err, errEndpointCAMissing) {
			r.logger.Error(err, "Skipping securityconfig reconciliation")
			r.recorder.AnnotatedEventf(r.instance, annotations, "Warning", "Security", "%s", err.Error())
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	r.logger.Info("Starting securityconfig update job")
	r.recorder.AnnotatedEventf(r.instance, annotations, "Normal", "Security", "Starting securityconfig update job")

	job = builders.NewSecurityconfigUpdateJob(
		r.instance,
		jobName,
		namespace,
		checksumval,
		adminCertName,
		endpointCASecretName,
		cmdArg,
		r.reconcilerContext.Volumes,
		r.reconcilerContext.VolumeMounts,
	)

	if err := ctrl.SetControllerReference(r.instance, &job, r.client.Scheme()); err != nil {
		return ctrl.Result{}, err
	}

	_, err = r.client.CreateJob(&job)
	return ctrl.Result{}, err
}

// BuildCmdArg builds the command for the securityconfig-update job for each individual ymls present in the
// securityconfig secret. yml files which are not present in the secret are not applied/updated
func BuildCmdArg(instance *opsterv1.OpenSearchCluster, secret *corev1.Secret, log logr.Logger) string {
	clusterHostName := BuildClusterSvcHostName(instance)
	httpPort, securityConfigPort, securityconfigPath := helpers.VersionCheck(instance)

	arg := fmt.Sprintf(SecurityAdminBaseCmdTmpl, clusterHostName, httpPort)

	// Get the list of yml files and sort them
	// This will ensure commands are always generated in the same order
	// Needed for tests as well to compare actual and expected command
	keys := make([]string, 0, len(secret.Data))
	for k := range secret.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		filePath := fmt.Sprintf("%s/%s", securityconfigPath, k)
		fileType, ok := ymlToFileType[k]
		if !ok {
			// If the yml file is invalid, do not return the error
			// Just log it and build the commands for valid yml files
			log.Error(fmt.Errorf("invalid yml file %s in securityconfig secret", k), fmt.Sprintf("skipping %s", k))
			continue
		}
		// Necessary as kubectl apply for stringData doesn't completely remove the field from the secret
		// Even if the field was removed from the yaml file it was applied from
		// Instead it sets it to an empty value
		if string(secret.Data[k]) != "" {
			arg = arg + fmt.Sprintf(ApplySingleYmlCmdTmpl, caCert, adminCert, adminKey, filePath, fileType, clusterHostName, securityConfigPort)
		}
	}

	return arg
}

func checksum(data map[string][]byte) (string, error) {
	hash := sha1.New()
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		_, err := hash.Write([]byte(key))
		if err != nil {
			return "", err
		}
		value := data[key]
		_, err = hash.Write(value)
		if err != nil {
			return "", err
		}
	}
	return base64.StdEncoding.EncodeToString(hash.Sum(nil)), nil
}

func (r *SecurityconfigReconciler) determineAdminSecret() string {
	if r.instance.Spec.Security.Config != nil && r.instance.Spec.Security.Config.AdminSecret.Name != "" {
		return r.instance.Spec.Security.Config.AdminSecret.Name
	} else if r.instance.Spec.Security.Tls != nil && r.instance.Spec.Security.Tls.Transport != nil && r.instance.Spec.Security.Tls.Transport.Generate {
		return fmt.Sprintf("%s-admin-cert", r.instance.Name)
	} else {
		return ""
	}
}

func (r *SecurityconfigReconciler) DeleteResources() (ctrl.Result, error) {
	result := reconciler.CombinedResult{}
	return result.Result, result.Err
}

func (r *SecurityconfigReconciler) securityconfigSubpaths(instance *opsterv1.OpenSearchCluster, secret *corev1.Secret) error {
	r.reconcilerContext.Volumes = append(r.reconcilerContext.Volumes, corev1.Volume{
		Name: "securityconfig",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: secret.Name,
			},
		},
	})

	keys := make([]string, 0, len(secret.Data))
	for k := range secret.Data {
		keys = append(keys, k)
	}
	_, _, securityconfigPath := helpers.VersionCheck(instance)
	sort.Strings(keys)
	for _, k := range keys {
		r.reconcilerContext.VolumeMounts = append(r.reconcilerContext.VolumeMounts, corev1.VolumeMount{
			Name:      "securityconfig",
			MountPath: fmt.Sprintf("%s/%s", securityconfigPath, k),
			SubPath:   k,
			ReadOnly:  true,
		})
	}

	return nil
}

// BuildClusterSvcHostName builds the cluster host name as {svc-name}.{namespace}.svc.{dns-base}
func BuildClusterSvcHostName(instance *opsterv1.OpenSearchCluster) string {
	return fmt.Sprintf("%s.svc.%s", builders.DnsOfService(instance), helpers.ClusterDnsBase())
}

// determineEndpointCASecret returns the secret whose ca.crt securityadmin uses to
// verify the OpenSearch endpoint: HTTP for OpenSearch 2.x, transport for earlier versions.
func (r *SecurityconfigReconciler) determineEndpointCASecret() string {
	tlsConfig := r.instance.Spec.Security.Tls
	if tlsConfig == nil {
		return ""
	}
	if helpers.SecurityChangeVersion(r.instance) {
		return helpers.HTTPEndpointCACertSecretRef(r.instance.Name, tlsConfig.Http).Name
	}
	return helpers.TransportEndpointCACertSecretRef(r.instance.Name, tlsConfig.Transport).Name
}

func (r *SecurityconfigReconciler) warnEndpointCAFallback(endpointSecretName, fallbackName string, annotations map[string]string) {
	r.logger.Info("Endpoint secret has no ca.crt, falling back", "secret", endpointSecretName, "fallback", fallbackName)
	r.recorder.AnnotatedEventf(r.instance, annotations, "Warning", "Security",
		"Secret '%s' has no %s, using '%s' to verify the endpoint; add %s to '%s' to silence this",
		endpointSecretName, CaCertKey, fallbackName, CaCertKey, endpointSecretName)
}

var errEndpointCAMissing = errors.New("endpoint CA certificate not found")

// resolveEndpointCASecret returns the name of the secret whose ca.crt securityadmin uses
// to verify the OpenSearch endpoint. The endpoint certificate secret is preferred. If it
// has no ca.crt (e.g. ACME issuers), it falls back to what securityadmin used before the
// endpoint CA was introduced: the configured caSecret, then the admin secret itself.
func (r *SecurityconfigReconciler) resolveEndpointCASecret(namespace, adminSecretName string, annotations map[string]string) (string, error) {
	endpointSecretName := r.determineEndpointCASecret()
	caSecretName := helpers.TlsCASecretRef(r.instance).Name

	// 1. The endpoint certificate secret (the prefered source)
	if endpointSecretName != "" {
		secret, err := r.client.GetSecret(endpointSecretName, namespace)
		if err != nil {
			return "", err
		} else if len(secret.Data[CaCertKey]) > 0 {
			return endpointSecretName, nil
		}
	}

	// first fallback alternative: the configured caSecret if present
	if caSecretName != "" && caSecretName != endpointSecretName {
		secret, err := r.client.GetSecret(caSecretName, namespace)
		if err != nil {
			return "", err
		} else if len(secret.Data[CaCertKey]) > 0 {
			r.warnEndpointCAFallback(endpointSecretName, caSecretName, annotations)
			return caSecretName, nil
		}
	}

	// second fallback alternative: the admin secret if present
	if adminSecretName != "" && adminSecretName != endpointSecretName && adminSecretName != caSecretName {
		secret, err := r.client.GetSecret(adminSecretName, namespace)
		if err != nil {
			return "", err
		} else if len(secret.Data[CaCertKey]) > 0 {
			r.warnEndpointCAFallback(endpointSecretName, adminSecretName, annotations)
			return adminSecretName, nil
		}
	}

	return "", fmt.Errorf("%w: secret '%s' (or, as fallback, caSecret '%s' or admin secret '%s') must contain a non-empty %s for securityadmin to verify the endpoint",
		errEndpointCAMissing, endpointSecretName, caSecretName, adminSecretName, CaCertKey)
}
