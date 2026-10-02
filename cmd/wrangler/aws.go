package main

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/volck/raven/internal/provision"
)

// awsSettings are the writeback values shared by every raven in the cluster.
// The credentials are deliberately absent: they differ per raven and are read
// from a Secret.
type awsSettings struct {
	Region       string
	SecretPrefix string
	RoleName     string
}

func (a awsSettings) complete() error {
	missing := []string{}
	for name, value := range map[string]string{
		"region":       a.Region,
		"secretPrefix": a.SecretPrefix,
		"roleName":     a.RoleName,
	} {
		if value == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("aws writeback requested but wrangler is missing %v", missing)
	}
	return nil
}

// awsCredentialsSecretName is the Secret holding this raven's IAM credentials.
// Wrangler never creates it; the credentials are issued out of band.
func awsCredentialsSecretName(spec provision.RavenSpec) string {
	return "aws-" + spec.Name + "-credentials"
}

// awsEnv returns the writeback variables, or nothing when the switch is off.
func (a *clusterApplier) awsEnv(spec provision.RavenSpec) []corev1.EnvVar {
	if !spec.AWSWriteback {
		return nil
	}

	env := []corev1.EnvVar{
		{Name: "AWS_WRITEBACK", Value: "true"},
		{Name: "AWS_REGION", Value: a.defaults.AWS.Region},
		{Name: "AWS_SECRET_PREFIX", Value: a.defaults.AWS.SecretPrefix},
		{Name: "AWS_ROLE_NAME", Value: a.defaults.AWS.RoleName},
	}
	for _, key := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"} {
		env = append(env, corev1.EnvVar{
			Name: key,
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: awsCredentialsSecretName(spec)},
					Key:                  key,
				},
			},
		})
	}
	return env
}
