package helpers

import (
	"fmt"

	opsterv1 "github.com/Opster/opensearch-k8s-operator/opensearch-operator/api/v1"
	version "github.com/hashicorp/go-version"
	corev1 "k8s.io/api/core/v1"
)

// SecurityChangeVersion reports whether the cluster runs OpenSearch >= 2.0.
// An unparsable version is treated as >= 2.0, like upstream.
func SecurityChangeVersion(cluster *opsterv1.OpenSearchCluster) bool {
	v, err := version.NewVersion(cluster.Spec.General.Version)
	if err != nil {
		return true
	}
	c, err := version.NewConstraint(">= 2.0")
	if err != nil {
		return true
	}
	return c.Check(v)
}

// TlsCASecretRef returns the CA secret reference used to sign the admin certificate.
// OpenSearch 2.x uses the HTTP CA; earlier versions use the transport CA.
func TlsCASecretRef(cluster *opsterv1.OpenSearchCluster) corev1.LocalObjectReference {
	if cluster == nil || cluster.Spec.Security == nil || cluster.Spec.Security.Tls == nil {
		return corev1.LocalObjectReference{}
	}
	if SecurityChangeVersion(cluster) {
		if cluster.Spec.Security.Tls.Http != nil {
			return cluster.Spec.Security.Tls.Http.CaSecret
		}
		return corev1.LocalObjectReference{}
	}
	if cluster.Spec.Security.Tls.Transport != nil {
		return cluster.Spec.Security.Tls.Transport.CaSecret
	}
	return corev1.LocalObjectReference{}
}

// HTTPEndpointCACertSecretRef returns the secret containing the CA certificate
// used to verify the OpenSearch HTTP endpoint.
func HTTPEndpointCACertSecretRef(clusterName string, tlsConfig *opsterv1.TlsConfigHttp) corev1.LocalObjectReference {
	if tlsConfig == nil {
		return corev1.LocalObjectReference{}
	}
	if tlsConfig.Generate {
		return corev1.LocalObjectReference{Name: fmt.Sprintf("%s-http-cert", clusterName)}
	}
	return tlsConfig.Secret
}

// TransportEndpointCACertSecretRef returns the secret containing the CA
// certificate used to verify the OpenSearch transport endpoint.
func TransportEndpointCACertSecretRef(clusterName string, tlsConfig *opsterv1.TlsConfigTransport) corev1.LocalObjectReference {
	if tlsConfig == nil {
		return corev1.LocalObjectReference{}
	}
	if tlsConfig.Generate {
		return corev1.LocalObjectReference{Name: fmt.Sprintf("%s-transport-cert", clusterName)}
	}
	return tlsConfig.Secret
}
