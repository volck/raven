package k8s

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	appsv1 "k8s.io/api/apps/v1"
	authorization "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/volck/raven/internal/config"
	"github.com/volck/raven/internal/helpers"
	vaultpkg "github.com/volck/raven/internal/vault"
)

var jsonLogger = helpers.JsonLogger
var Added = make(chan string)

// K8sEvent represents a lifecycle event from the K8s namespace watcher.
type K8sEvent struct {
	Type      string // "k8s-added", "k8s-modified", "k8s-deleted", "k8s-rollout"
	Secret    string
	Namespace string
	Message   string
}

type Watcher struct {
	Logger    *slog.Logger
	ClientSet kubernetes.Interface
	Namespace string
	OnEvent   func(K8sEvent) // optional callback for lifecycle events
}

func NewWatcher(logger *slog.Logger, clientSet kubernetes.Interface, namespace string) *Watcher {
	logger.Info("Initialising kubernetes watcher")
	return &Watcher{Logger: logger, ClientSet: clientSet, Namespace: namespace}
}

func ApplyAnnotations(dataFields *api.Secret, cfg config.Config) map[string]string {
	Annotations := make(map[string]string)
	Annotations["source"] = cfg.SecretEngine
	if len(dataFields.Data["metadata"].(map[string]interface{})) == 0 {
		jsonLogger.Debug("No datafields applied", "len(data[metadata]", len(dataFields.Data))
	} else {
		for k, v := range dataFields.Data["metadata"].(map[string]interface{}) {
			switch val := v.(type) {
			case float64:
				Annotations[k] = strconv.FormatFloat(val, 'f', -1, 64)
			case int:
				Annotations[k] = strconv.Itoa(val)
			case string:
				Annotations[k] = val
			case bool:
				Annotations[k] = strconv.FormatBool(val)
			case map[string]interface{}:
				jsonBytes, err := json.Marshal(val)
				if err != nil {
					jsonLogger.Warn("failed to marshal nested map in metadata to JSON", "key", k, "error", err)
					continue
				}
				Annotations[k] = string(jsonBytes)
			case nil:
				jsonLogger.Debug("skipping nil value in metadata", "key", k)
			default:
				jsonLogger.Debug("unsupported metadata value type", "key", k, "type", reflect.TypeOf(v))
			}
		}
	}
	return Annotations
}

func ApplyDatafieldsTok8sSecret(dataFields *api.Secret, Annotations map[string]string, name string, documentationKeys []string) (data map[string][]byte, stringdata map[string]string) {
	stringdata = make(map[string]string)
	data = make(map[string][]byte)
	if dataFields.Data["data"] == nil {
		jsonLogger.Debug("Trying to apply data fields to kubernetes secret, but vault datafields seem to be empty.", "secret", name)
	} else if len(dataFields.Data["data"].(map[string]interface{})) == 0 {
		jsonLogger.Debug("Trying to apply datafields to kubernetes secret, but no datafields could be placed.", "secret", name)
		return data, stringdata
	} else {
		for k, v := range dataFields.Data["data"].(map[string]interface{}) {
			jsonLogger.Debug("createK8sSecret: dataFields.Data[data] iterate", "key", k, "value", v)

			var valueStr string
			switch val := v.(type) {
			case string:
				valueStr = val
			case map[string]interface{}:
				jsonBytes, err := json.Marshal(val)
				if err != nil {
					jsonLogger.Warn("failed to marshal nested map to JSON", "key", k, "error", err)
					continue
				}
				valueStr = string(jsonBytes)
			case []interface{}, []string, []int, []float64, []bool:
				jsonBytes, err := json.Marshal(val)
				if err != nil {
					jsonLogger.Warn("failed to marshal array to JSON", "key", k, "error", err)
					continue
				}
				valueStr = string(jsonBytes)
			case float64:
				valueStr = strconv.FormatFloat(val, 'f', -1, 64)
			case int:
				valueStr = strconv.Itoa(val)
			case bool:
				valueStr = strconv.FormatBool(val)
			case nil:
				jsonLogger.Debug("skipping nil value in secret data", "key", k)
				continue
			default:
				jsonBytes, err := json.Marshal(val)
				if err != nil {
					jsonLogger.Warn("unsupported value type in secret data", "key", k, "type", reflect.TypeOf(v))
					continue
				}
				valueStr = string(jsonBytes)
			}

			if strings.HasPrefix(valueStr, "base64:") {
				stringSplit := strings.Split(valueStr, ":")
				if helpers.IsBase64(stringSplit[1]) {
					data[k], _ = base64.StdEncoding.DecodeString(stringSplit[1])
				} else {
					jsonLogger.Warn("key is not valid BASE64", "key", k)
				}
			} else if helpers.IsDocumentationKey(documentationKeys, k) {
				Annotations[k] = valueStr
			} else {
				stringdata[k] = valueStr
			}
		}
	}
	return data, stringdata
}

func ApplyRavenLabels() map[string]string {
	labels := make(map[string]string)
	labels["managedBy"] = "raven"
	return labels
}

func ApplyMetadata(dataFields *api.Secret, Annotations map[string]string) map[string]string {
	if len(dataFields.Data["metadata"].(map[string]interface{})) == 0 {
		jsonLogger.Debug("No metadata placed")
		return Annotations
	}
	for k, v := range dataFields.Data["metadata"].(map[string]interface{}) {
		switch val := v.(type) {
		case float64:
			Annotations[k] = strconv.FormatFloat(val, 'f', -1, 64)
		case string:
			Annotations[k] = val
		case bool:
			Annotations[k] = strconv.FormatBool(val)
		}
	}

	_, customMetadataFound := vaultpkg.GetCustomMetadataFromSecret(dataFields)
	if customMetadataFound {
		for k, v := range dataFields.Data["metadata"].(map[string]interface{})["custom_metadata"].(map[string]interface{}) {
			switch val := v.(type) {
			case float64:
				Annotations[k] = strconv.FormatFloat(val, 'f', -1, 64)
			case string:
				Annotations[k] = val
			case bool:
				Annotations[k] = strconv.FormatBool(val)
			}
		}
	}
	return Annotations
}

func NewSecretWithContents(contents config.SecretContents, cfg config.Config) v1.Secret {
	secret := v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SealedSecret",
			APIVersion: "bitnami.com/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        contents.Name,
			Namespace:   cfg.DestEnv,
			Annotations: contents.Annotations,
			Labels:      contents.Labels,
		},
		Data:       contents.Data,
		StringData: contents.StringData,
		Type:       "Opaque",
	}
	return secret
}

func NewKubernetesClient() *kubernetes.Clientset {
	k8sConfig, err := rest.InClusterConfig()
	if err != nil {
		jsonLogger.Error("NewKubernetesClient incluster config failed", "error", err)
	}
	Clientset, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		jsonLogger.Error("NewKubernetesClient clientset failed", "error", err)
	}
	return Clientset
}

func KubernetesSecretList(c kubernetes.Interface, destEnv string) (*v1.SecretList, error) {
	sl, err := c.CoreV1().Secrets(destEnv).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		jsonLogger.Error("clientset secrets error", "error", err)
	}
	return sl, err
}

func Hask8sRavenLabel(secret v1.Secret) bool {
	return secret.Labels["managedBy"] == "raven"
}

func KubernetesRemove(ripeSecrets []string, kubernetesSecretList *v1.SecretList, clientSet kubernetes.Interface, destEnv string) {
	kubernetesRemoveEnv := os.Getenv("KUBERNETESREMOVE")
	if kubernetesRemoveEnv == "true" {
		for _, k8sSecret := range kubernetesSecretList.Items {
			if helpers.StringSliceContainsString(ripeSecrets, k8sSecret.Name) && Hask8sRavenLabel(k8sSecret) {
				jsonLogger.Info("Secret no longer available in vault or in git. Removing from Kubernetes namespace.",
					"secret", k8sSecret.Name, "action", "kubernetes.delete", "namespace", destEnv)

				err := clientSet.CoreV1().Secrets(destEnv).Delete(context.TODO(), k8sSecret.Name, metav1.DeleteOptions{})
				if err != nil {
					jsonLogger.Error("kubernetesRemove clientsetDelete in namespace failed", "error", err.Error())
				}
			}
		}
	}
}

func SearchKubernetesForResults(ctx context.Context, Mysecret string, cfg config.Config) {
	kubernetesMonitor := os.Getenv("KUBERNETESMONITOR")
	if kubernetesMonitor == "true" {
		watcher, err := cfg.Clientset.CoreV1().Secrets(cfg.DestEnv).Watch(context.Background(), metav1.ListOptions{})
		if err != nil {
			jsonLogger.Error("searchKubernetesForResults timeout", "error", err)
		}
		for event := range watcher.ResultChan() {
			secretObject := event.Object.(*v1.Secret)
			switch event.Type {
			case watch.Added:
				Added <- secretObject.ObjectMeta.Name
			}
		}
	}
}

func InitKubernetesSearch(secret string, cfg config.Config) {
	kubernetesMonitor := os.Getenv("KUBERNETESMONITOR")
	if kubernetesMonitor == "true" {
		ctx := context.Background()
		ctxWithTimeout, cancel := context.WithTimeout(ctx, time.Duration(5)*time.Minute)
		go SearchKubernetesForResults(ctxWithTimeout, secret, cfg)
		defer cancel()
	}
}

func MonitorMessages(watchlist []string) {
	kubernetesMonitor := os.Getenv("KUBERNETESMONITOR")
	if kubernetesMonitor == "true" {
		jsonLogger.Info("Raven starting search for secret in namespace", "action", "kubernetes.lookup.secret.start", "secret", watchlist)
		for {
			select {
			case addedSecret := <-Added:
				if helpers.StringSliceContainsString(watchlist, addedSecret) {
					jsonLogger.Info("Raven found secret in kubernetes namespace", "action", "kubernetes.lookup.secret.success", "secret", addedSecret)
				}
			}
		}
	}
}

func CreateK8sSecret(name string, cfg config.Config, dataFields *api.Secret) v1.Secret {
	Annotations := ApplyAnnotations(dataFields, cfg)
	data, stringdata := ApplyDatafieldsTok8sSecret(dataFields, Annotations, name, cfg.DocumentationKeys)
	Annotations = ApplyMetadata(dataFields, Annotations)
	ravenLabels := ApplyRavenLabels()

	SecretContent := config.SecretContents{StringData: stringdata, Data: data, Annotations: Annotations, Name: name, Labels: ravenLabels}
	secret := NewSecretWithContents(SecretContent, cfg)
	jsonLogger.Debug("createK8sSecret: made k8s secret object",
		"typeMeta", secret.TypeMeta,
		"objectMeta", secret.ObjectMeta,
		"data", data,
		"stringData", stringdata,
		"secret", secret)
	return secret
}

// Watcher methods

func (app *Watcher) CheckKubernetesServiceAccountPermissions() bool {
	ctx := context.Background()
	verbs := []string{"get", "watch", "list", "update", "patch"}
	type resourceCheck struct {
		group    string
		resource string
	}
	checks := []resourceCheck{
		{"", "secrets"},
		{"apps", "deployments"},
		{"apps", "statefulsets"},
	}

	ssars := []*authorization.SelfSubjectAccessReview{}
	for _, verb := range verbs {
		for _, rc := range checks {
			ssar := &authorization.SelfSubjectAccessReview{
				Spec: authorization.SelfSubjectAccessReviewSpec{
					ResourceAttributes: &authorization.ResourceAttributes{
						Namespace: app.Namespace,
						Verb:      verb,
						Group:     rc.group,
						Resource:  rc.resource,
					},
				},
			}
			ssars = append(ssars, ssar)
		}
	}

	decision := false
	for _, ssar := range ssars {
		ssar, err := app.ClientSet.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, ssar, metav1.CreateOptions{})
		if err != nil {
			jsonLogger.Error("Failed to check permissions", slog.String("error", err.Error()), slog.String("namespace", app.Namespace))
			decision = false
		}
		if ssar.Status.Allowed {
			decision = true
		} else {
			jsonLogger.Error("Service account not allowed to perform action",
				slog.String("namespace", app.Namespace),
				slog.Any("verb", ssar.Spec.ResourceAttributes.Verb),
				slog.Any("resource", ssar.Spec.ResourceAttributes.Resource))
		}
	}
	return decision
}

func (app *Watcher) MonitorNamespaceForSecretChange() {
	ctx := context.Background()
	jsonLogger.Info("Started monitoring for secrets in kubernetes", slog.String("namespace", app.Namespace))
	if app.ClientSet != nil {
		theSecretWatcher, err := app.ClientSet.CoreV1().Secrets(app.Namespace).Watch(ctx, metav1.ListOptions{})
		if err != nil {
			jsonLogger.Error("Failed to watch for secrets", slog.String("error", err.Error()), slog.String("namespace", app.Namespace))
		}
		go app.handleSecretEvents(theSecretWatcher, ctx)
	}
}

func (app *Watcher) handleSecretEvents(watcher watch.Interface, ctx context.Context) {
	for event := range watcher.ResultChan() {
		if secret, ok := event.Object.(*corev1.Secret); ok {
			app.handleSecretEvent(secret, event.Type, ctx)
		}
	}
}

func (app *Watcher) handleSecretEvent(secret *corev1.Secret, eventType watch.EventType, ctx context.Context) {
	if secret == nil || secret.ObjectMeta.Labels["managedBy"] != "raven" {
		return
	}

	recentlyAdded := false
	for _, mf := range secret.ObjectMeta.ManagedFields {
		if time.Since(mf.Time.Time).Minutes() < 3 {
			recentlyAdded = true
			break
		}
	}

	if !recentlyAdded {
		return
	}

	switch eventType {
	case watch.Added, watch.Modified:
		op := "k8s-added"
		if eventType == watch.Modified {
			op = "k8s-modified"
		}
		if app.OnEvent != nil {
			app.OnEvent(K8sEvent{Type: op, Secret: secret.Name, Namespace: secret.Namespace, Message: "secret " + string(eventType) + " in cluster"})
		}
		app.checkResources(secret, string(eventType), ctx)
	case watch.Deleted:
		jsonLogger.Info("secret was deleted", slog.String("secret", secret.Name), slog.String("namespace", secret.Namespace))
		if app.OnEvent != nil {
			app.OnEvent(K8sEvent{Type: "k8s-deleted", Secret: secret.Name, Namespace: secret.Namespace, Message: "secret removed from cluster"})
		}
	}
}

func (app *Watcher) checkResources(secret *corev1.Secret, eventType string, ctx context.Context) {
	if secret == nil {
		return
	}
	jsonLogger.Info("Checking resources", slog.String("secret", secret.Name), slog.String("namespace", secret.Namespace), slog.String("eventType", eventType))
	app.checkStatefulSets(secret, eventType, ctx)
	app.checkDeployments(secret, eventType, ctx)
}

func (app *Watcher) checkStatefulSets(secret *corev1.Secret, eventType string, ctx context.Context) {
	allStateFulSets, _ := app.ClientSet.AppsV1().StatefulSets(app.Namespace).List(ctx, metav1.ListOptions{})
	for _, stateful := range allStateFulSets.Items {
		for _, v := range stateful.Spec.Template.Spec.Volumes {
			if v.Secret != nil && v.Secret.SecretName == secret.Name {
				app.TriggerRollout(nil, &stateful, secret)
			}
		}
	}
}

func (app *Watcher) checkDeployments(secret *corev1.Secret, eventType string, ctx context.Context) {
	allDeployments, _ := app.ClientSet.AppsV1().Deployments(app.Namespace).List(ctx, metav1.ListOptions{})
	for _, dep := range allDeployments.Items {
		for _, v := range dep.Spec.Template.Spec.Volumes {
			if v.Secret != nil && v.Secret.SecretName == secret.Name {
				app.TriggerRollout(&dep, nil, secret)
			}
		}
	}
}

func (app *Watcher) TriggerRollout(deployment *appsv1.Deployment, statefulset *appsv1.StatefulSet, secret *v1.Secret) {
	if deployment != nil {
		deployment = app.updateDeploymentAnnotations(deployment, secret)
		_, err := app.ClientSet.AppsV1().Deployments(app.Namespace).Update(context.Background(), deployment, metav1.UpdateOptions{})
		if err != nil {
			jsonLogger.Error("failed to update deployment", slog.String("error", err.Error()), slog.String("deployment", deployment.Name))
		} else if app.OnEvent != nil {
			app.OnEvent(K8sEvent{Type: "k8s-rollout", Secret: secret.Name, Namespace: secret.Namespace, Message: "rollout restart: deployment/" + deployment.Name})
		}
		jsonLogger.Info("Rollout restart triggered for deployment", slog.String("deployment", deployment.Name), slog.String("namespace", deployment.Namespace))
	} else if statefulset != nil {
		statefulset = app.updateStatefulSetAnnotations(statefulset, secret)
		_, err := app.ClientSet.AppsV1().StatefulSets(app.Namespace).Update(context.Background(), statefulset, metav1.UpdateOptions{})
		if err != nil {
			jsonLogger.Error("failed to update statefulset", slog.String("error", err.Error()), slog.String("statefulset", statefulset.Name))
		} else if app.OnEvent != nil {
			app.OnEvent(K8sEvent{Type: "k8s-rollout", Secret: secret.Name, Namespace: secret.Namespace, Message: "rollout restart: statefulset/" + statefulset.Name})
		}
		jsonLogger.Info("Rollout restart triggered for statefulset", slog.String("statefulSet", statefulset.Name), slog.String("namespace", statefulset.Namespace))
	}
}

func (app *Watcher) updateDeploymentAnnotations(deployment *appsv1.Deployment, secret *v1.Secret) *appsv1.Deployment {
	if deployment.Spec.Template.ObjectMeta.Annotations == nil {
		deployment.Spec.Template.ObjectMeta.Annotations = make(map[string]string)
	}
	if deployment.Spec.Template.ObjectMeta.Annotations["norsk-tipping.no/lastUUIDTriggeredRestart"] == "" || deployment.Spec.Template.ObjectMeta.Annotations["norsk-tipping.no/lastUUIDTriggeredRestart"] != string(secret.ObjectMeta.UID) {
		deployment.Spec.Template.ObjectMeta.Annotations["kubectl.kubernetes.io/restartedAt"] = metav1.Now().String()
		deployment.Spec.Template.ObjectMeta.Annotations["openshift.openshift.io/restartedAt"] = metav1.Now().String()
		deployment.Spec.Template.ObjectMeta.Annotations["norsk-tipping.no/lastUUIDTriggeredRestart"] = string(secret.ObjectMeta.UID)
	}
	return deployment
}

func (app *Watcher) updateStatefulSetAnnotations(statefulset *appsv1.StatefulSet, secret *v1.Secret) *appsv1.StatefulSet {
	if statefulset.Spec.Template.ObjectMeta.Annotations == nil {
		statefulset.Spec.Template.ObjectMeta.Annotations = make(map[string]string)
	}
	if statefulset.Spec.Template.ObjectMeta.Annotations["norsk-tipping.no/lastUUIDTriggeredRestart"] == "" || statefulset.Spec.Template.ObjectMeta.Annotations["norsk-tipping.no/lastUUIDTriggeredRestart"] != string(secret.ObjectMeta.UID) {
		statefulset.Spec.Template.ObjectMeta.Annotations["openshift.openshift.io/restartedAt"] = metav1.Now().String()
		statefulset.Spec.Template.ObjectMeta.Annotations["kubectl.kubernetes.io/restartedAt"] = metav1.Now().String()
		statefulset.Spec.Template.ObjectMeta.Annotations["norsk-tipping.no/lastUUIDTriggeredRestart"] = string(secret.ObjectMeta.UID)
	}
	return statefulset
}
