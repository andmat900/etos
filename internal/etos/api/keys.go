// Copyright Axis Communications AB.
//
// For a full list of individual contributors, please see the commit history.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	etosv1alpha1 "github.com/eiffel-community/etos/api/v1alpha1"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	keysPort        int32 = 8080
	KeysServicePort int32 = 80
)

type ETOSKeysDeployment struct {
	etosv1alpha1.ETOSKeys
	client.Client
	Scheme          *runtime.Scheme
	restartRequired bool
}

// NewETOSKeysDeployment will create a new ETOS Keys reconciler.
func NewETOSKeysDeployment(spec etosv1alpha1.ETOSKeys, scheme *runtime.Scheme, client client.Client) *ETOSKeysDeployment {
	return &ETOSKeysDeployment{spec, client, scheme, false}
}

// GenerateRSAKeyPair generates a new RSA key pair and returns the PEM-encoded private and public keys
func (r *ETOSKeysDeployment) GenerateRSAKeyPair(keySize int) (privateKeyPEM, publicKeyPEM string, err error) {
	if keySize == 0 {
		keySize = 2048 // Default key size
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Encode private key to PEM format
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal private key: %w", err)
	}

	privateKeyPEMBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privateKeyPEM = string(pem.EncodeToMemory(privateKeyPEMBlock))

	// Extract public key and encode to PEM format
	publicKey := &privateKey.PublicKey
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEMBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicKeyPEM = string(pem.EncodeToMemory(publicKeyPEMBlock))

	return privateKeyPEM, publicKeyPEM, nil
}

// ShouldGenerateKeys checks if key generation is needed based on the cluster spec
func (r *ETOSKeysDeployment) ShouldGenerateKeys(ctx context.Context, namespace string) bool {
	// Check if both private and public keys are missing or empty
	privateKeyEmpty := r.isKeyEmpty(ctx, &r.PrivateKey, namespace)
	publicKeyEmpty := r.isKeyEmpty(ctx, &r.PublicKey, namespace)

	return privateKeyEmpty || publicKeyEmpty
}

// isKeyEmpty checks if a Var is empty (no value and no reference)
func (r *ETOSKeysDeployment) isKeyEmpty(ctx context.Context, keyVar *etosv1alpha1.Var, namespace string) bool {
	if keyVar.Value != "" {
		return false
	}
	if keyVar.ValueFrom.SecretKeyRef != nil || keyVar.ValueFrom.ConfigMapKeyRef != nil {
		// Try to get the value to see if it exists and is non-empty
		if value, err := keyVar.Get(ctx, r.Client, namespace); err == nil && len(value) > 0 {
			return false
		}
	}
	return true
}

// Reconcile will reconcile the ETOS Keys service to its expected state.
func (r *ETOSKeysDeployment) Reconcile(ctx context.Context, cluster *etosv1alpha1.Cluster) error {
	var err error
	name := fmt.Sprintf("%s-etos-keys", cluster.Name)
	logger := log.FromContext(ctx, "Reconciler", "ETOSKeys", "BaseName", name)
	namespacedName := types.NamespacedName{Name: name, Namespace: cluster.Namespace}

	cfg, err := r.reconcileConfig(ctx, logger, namespacedName, cluster)
	if err != nil {
		logger.Error(err, "Failed to reconcile the config for the ETOS Keys")
		return err
	}
	_, err = r.reconcileDeployment(ctx, logger, namespacedName, cfg.ObjectMeta.Name, cluster)
	if err != nil {
		logger.Error(err, "Failed to reconcile the deployment for the ETOS Keys")
		return err
	}

	_, err = r.reconcileRole(ctx, logger, namespacedName, cluster)
	if err != nil {
		logger.Error(err, "Failed to reconcile the role for the ETOS Keys")
		return err
	}
	_, err = r.reconcileServiceAccount(ctx, logger, namespacedName, cluster)
	if err != nil {
		logger.Error(err, "Failed to reconcile the service account for the ETOS Keys")
		return err
	}
	_, err = r.reconcileRolebinding(ctx, logger, namespacedName, cluster)
	if err != nil {
		logger.Error(err, "Failed to reconcile the role binding for the ETOS Keys")
		return err
	}
	_, err = r.reconcileService(ctx, logger, namespacedName, cluster)
	if err != nil {
		logger.Error(err, "Failed to reconcile the service for the ETOS Keys")
		return err
	}
	return nil
}

// reconcileConfig will reconcile the secret to use as configuration for the ETOS Keys.
func (r *ETOSKeysDeployment) reconcileConfig(ctx context.Context, logger logr.Logger, name types.NamespacedName, owner metav1.Object) (*corev1.Secret, error) {
	name = types.NamespacedName{Name: fmt.Sprintf("%s-cfg", name.Name), Namespace: name.Namespace}
	target, err := r.config(ctx, name)
	if err != nil {
		return nil, err
	}
	if err := ctrl.SetControllerReference(owner, target, r.Scheme); err != nil {
		return target, err
	}

	secret := &corev1.Secret{}
	if err := r.Get(ctx, name, secret); err != nil {
		if !apierrors.IsNotFound(err) {
			return secret, err
		}
		r.restartRequired = true
		logger.Info("Creating a new config for the ETOS Keys")
		if err := r.Create(ctx, target); err != nil {
			return target, err
		}
		return target, nil
	}
	if equality.Semantic.DeepDerivative(target.Data, secret.Data) {
		return secret, nil
	}
	r.restartRequired = true
	return target, r.Patch(ctx, target, client.StrategicMergeFrom(secret))
}

// reconcileDeployment will reconcile the ETOS Keys deployment to its expected state.
func (r *ETOSKeysDeployment) reconcileDeployment(ctx context.Context, logger logr.Logger, name types.NamespacedName, secretName string, owner metav1.Object) (*appsv1.Deployment, error) {
	target := r.deployment(name, secretName)
	if err := ctrl.SetControllerReference(owner, target, r.Scheme); err != nil {
		return target, err
	}
	scheme.Scheme.Default(target)

	deployment := &appsv1.Deployment{}
	if err := r.Get(ctx, name, deployment); err != nil {
		if !apierrors.IsNotFound(err) {
			return deployment, err
		}
		logger.Info("Creating a new deployment for the Keys server")
		if err := r.Create(ctx, target); err != nil {
			return target, err
		}
		return target, nil
	} else if r.restartRequired {
		logger.Info("Configuration(s) have changed, restarting deployment")
		if deployment.Spec.Template.Annotations == nil {
			deployment.Spec.Template.Annotations = make(map[string]string)
		}
		deployment.Spec.Template.Annotations["etos.eiffel-community.github.io/restartedAt"] = time.Now().Format(time.RFC3339)
	}
	if !r.restartRequired && equality.Semantic.DeepDerivative(target.Spec, deployment.Spec) {
		return deployment, nil
	}
	return target, r.Patch(ctx, target, client.StrategicMergeFrom(deployment))
}

// reconcileRole will reconcile the ETOS Keys service account role to its expected state.
func (r *ETOSKeysDeployment) reconcileRole(ctx context.Context, logger logr.Logger, name types.NamespacedName, owner metav1.Object) (*rbacv1.Role, error) {
	labelName := name.Name
	name.Name = fmt.Sprintf("%s:sa:keys-service", name.Name)

	target := r.role(name, labelName)
	if err := ctrl.SetControllerReference(owner, target, r.Scheme); err != nil {
		return target, err
	}

	role := &rbacv1.Role{}
	if err := r.Get(ctx, name, role); err != nil {
		if !apierrors.IsNotFound(err) {
			return role, err
		}
		logger.Info("Creating a new role for the Keys server")
		if err := r.Create(ctx, target); err != nil {
			return target, err
		}
		return target, nil
	}
	return target, r.Patch(ctx, target, client.StrategicMergeFrom(role))
}

// reconcileServiceAccount will reconcile the ETOS Keys service account to its expected state.
func (r *ETOSKeysDeployment) reconcileServiceAccount(ctx context.Context, logger logr.Logger, name types.NamespacedName, owner metav1.Object) (*corev1.ServiceAccount, error) {
	target := r.serviceaccount(name)
	if err := ctrl.SetControllerReference(owner, target, r.Scheme); err != nil {
		return target, err
	}

	serviceaccount := &corev1.ServiceAccount{}
	if err := r.Get(ctx, name, serviceaccount); err != nil {
		if !apierrors.IsNotFound(err) {
			return serviceaccount, err
		}
		logger.Info("Creating a new service account for the Keys server")
		if err := r.Create(ctx, target); err != nil {
			return target, err
		}
		return target, nil
	}
	return target, r.Patch(ctx, target, client.StrategicMergeFrom(serviceaccount))
}

// reconcileRolebinding will reconcile the ETOS Keys service account rolebinding to its expected state.
func (r *ETOSKeysDeployment) reconcileRolebinding(ctx context.Context, logger logr.Logger, name types.NamespacedName, owner metav1.Object) (*rbacv1.RoleBinding, error) {
	target := r.rolebinding(name)
	if err := ctrl.SetControllerReference(owner, target, r.Scheme); err != nil {
		return target, err
	}

	rolebinding := &rbacv1.RoleBinding{}
	if err := r.Get(ctx, name, rolebinding); err != nil {
		if !apierrors.IsNotFound(err) {
			return rolebinding, err
		}
		logger.Info("Creating a new role binding for the Keys server")
		if err := r.Create(ctx, target); err != nil {
			return target, err
		}
		return target, nil
	}
	return target, r.Patch(ctx, target, client.StrategicMergeFrom(rolebinding))
}

// reconcileService will reconcile the ETOS Keys service to its expected state.
func (r *ETOSKeysDeployment) reconcileService(ctx context.Context, logger logr.Logger, name types.NamespacedName, owner metav1.Object) (*corev1.Service, error) {
	target := r.service(name)
	if err := ctrl.SetControllerReference(owner, target, r.Scheme); err != nil {
		return target, err
	}
	service := &corev1.Service{}
	if err := r.Get(ctx, name, service); err != nil {
		if !apierrors.IsNotFound(err) {
			return service, err
		}
		logger.Info("Creating a new kubernetes service for the Keys server")
		if err := r.Create(ctx, target); err != nil {
			return target, err
		}
		return target, nil
	}
	return target, r.Patch(ctx, target, client.StrategicMergeFrom(service))
}

// role creates a role resource definition for the ETOS Keys service.
func (r *ETOSKeysDeployment) role(name types.NamespacedName, labelName string) *rbacv1.Role {
	meta := r.meta(types.NamespacedName{Name: labelName, Namespace: name.Namespace})
	meta.Name = name.Name
	meta.Annotations["rbac.authorization.kubernetes.io/autoupdate"] = "true"
	return &rbacv1.Role{
		ObjectMeta: meta,
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"secrets",
				},
				Verbs: []string{
					"get", "list", "watch", "create", "update", "patch",
				},
			},
		},
	}
}

// serviceaccount creates a serviceaccount resource definition for the ETOS Keys service.
func (r *ETOSKeysDeployment) serviceaccount(name types.NamespacedName) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: r.meta(name),
	}
}

// rolebinding creates a rolebinding resource definition for the ETOS Keys service.
func (r *ETOSKeysDeployment) rolebinding(name types.NamespacedName) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		ObjectMeta: r.meta(name),
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.SchemeGroupVersion.Group,
			Kind:     "Role",
			Name:     fmt.Sprintf("%s:sa:keys-service", name.Name),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind: "ServiceAccount",
				Name: name.Name,
			},
		},
	}
}

// deployment creates a deployment resource definition for the ETOS Keys service.
func (r *ETOSKeysDeployment) deployment(name types.NamespacedName, secretName string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: r.meta(name),
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/name":      name.Name,
					"app.kubernetes.io/part-of":   "etos",
					"app.kubernetes.io/component": "keys",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: r.meta(name),
				Spec: corev1.PodSpec{
					ServiceAccountName: name.Name,
					Containers:         []corev1.Container{r.container(name, secretName)},
				},
			},
		},
	}
}

// service creates a service resource definition for the ETOS Keys service.
func (r *ETOSKeysDeployment) service(name types.NamespacedName) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: r.meta(name),
		Spec: corev1.ServiceSpec{
			Ports: r.ports(),
			Selector: map[string]string{
				"app.kubernetes.io/name":      name.Name,
				"app.kubernetes.io/part-of":   "etos",
				"app.kubernetes.io/component": "keys",
			},
		},
	}
}

// container creates a container resource definition for the ETOS Keys deployment.
func (r *ETOSKeysDeployment) container(name types.NamespacedName, secretName string) corev1.Container {
	probe := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path:   "/keys/v1alpha/selftest/ping",
				Port:   intstr.FromString("http"),
				Scheme: "HTTP",
			},
		},
		TimeoutSeconds:   1,
		PeriodSeconds:    10,
		SuccessThreshold: 1,
		FailureThreshold: 3,
	}
	return corev1.Container{
		Name:            name.Name,
		Image:           r.Image.Image,
		ImagePullPolicy: r.ImagePullPolicy,
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse("256Mi"),
				corev1.ResourceCPU:    resource.MustParse("200m"),
			},
			Requests: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse("128Mi"),
				corev1.ResourceCPU:    resource.MustParse("100m"),
			},
		},
		Ports: []corev1.ContainerPort{
			{
				Name:          "http",
				ContainerPort: keysPort,
				Protocol:      "TCP",
			},
		},
		LivenessProbe:  probe,
		ReadinessProbe: probe,
		EnvFrom: []corev1.EnvFromSource{
			{
				SecretRef: &corev1.SecretEnvSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: secretName,
					},
				},
			},
		},
		Env: r.environment(),
	}
}

// environment creates an environment resource definition for the ETOS Keys deployment.
func (r *ETOSKeysDeployment) environment() []corev1.EnvVar {
	return []corev1.EnvVar{
		{
			Name:  "SERVICE_HOST",
			Value: "0.0.0.0",
		},
	}
}

// meta creates a common meta resource definition for the ETOS Keys service.
func (r *ETOSKeysDeployment) meta(name types.NamespacedName) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Labels: map[string]string{
			"app.kubernetes.io/name":      name.Name,
			"app.kubernetes.io/part-of":   "etos",
			"app.kubernetes.io/component": "keys",
		},
		Annotations: make(map[string]string),
		Name:        name.Name,
		Namespace:   name.Namespace,
	}
}

// config creates a new Secret to be used as configuration for the ETOS Keys.
func (r *ETOSKeysDeployment) config(ctx context.Context, name types.NamespacedName) (*corev1.Secret, error) {
	data := map[string][]byte{}

	// Check if we need to generate keys
	if r.ShouldGenerateKeys(ctx, name.Namespace) {
		logger := log.FromContext(ctx, "GenerateKeys", "ETOSKeys", "Namespace", name.Namespace)
		logger.Info("Generating new RSA key pair for ETOS Keys service")

		privateKeyPEM, publicKeyPEM, err := r.GenerateRSAKeyPair(2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
		}

		data["ETOS_KEYS_PRIVATE_KEY"] = []byte(privateKeyPEM)
		data["ETOS_KEYS_PUBLIC_KEY"] = []byte(publicKeyPEM)

		logger.Info("Successfully generated new RSA key pair for ETOS Keys service")
	} else {
		// Add public key configuration
		if publicKeyValue, err := r.PublicKey.Get(ctx, r.Client, name.Namespace); err == nil {
			data["ETOS_KEYS_PUBLIC_KEY"] = publicKeyValue
		} else {
			data["ETOS_KEYS_PUBLIC_KEY"] = []byte("")
		}

		// Add private key configuration
		if privateKeyValue, err := r.PrivateKey.Get(ctx, r.Client, name.Namespace); err == nil {
			data["ETOS_KEYS_PRIVATE_KEY"] = privateKeyValue
		} else {
			data["ETOS_KEYS_PRIVATE_KEY"] = []byte("")
		}
	}

	return &corev1.Secret{
		ObjectMeta: r.meta(name),
		Data:       data,
	}, nil
}

// ports creates a service port resource definition for the ETOS Keys service.
func (r *ETOSKeysDeployment) ports() []corev1.ServicePort {
	return []corev1.ServicePort{
		{Port: KeysServicePort, Name: "http", Protocol: "TCP", TargetPort: intstr.FromString("http")},
	}
}
