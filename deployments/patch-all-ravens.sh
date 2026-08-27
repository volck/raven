#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="ssg"
IMAGE="image-registry.openshift-image-registry.svc:5000/ssg/ravenunstable@sha256:48956b7ce003b4fe5409122eefc3bd94b129f329bd4abcfb8bd8e1cd3e0a0347"
SLEEP_TIME="3600"
SA="ssg-dev-cleaner"
OIDC_ISSUER_URL="https://auth.dev.norsk-tipping.no/auth/realms/vault"
OIDC_AUDIENCE="log-parser"
ARGOCD_SERVER="${ARGOCD_SERVER:-}"          # e.g. https://argocd.apps.ocpdq02.norsk-tipping.no
ARGOCD_APP_NAME="${ARGOCD_APP_NAME:-ssg}"  # ArgoCD Application name to sync
ARGOCD_SYNC_ENABLED="${ARGOCD_SYNC_ENABLED:-false}"
ARGOCD_TOKEN_SECRET="${ARGOCD_TOKEN_SECRET:-argocd-token}"  # K8s Secret holding 'token'
SKIP="ssg-prod01"

# Auto-detect cluster apps domain from ingress config
APPS_DOMAIN=$(oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}')
if [[ -z "$APPS_DOMAIN" ]]; then
  echo "ERROR: could not detect cluster apps domain" >&2
  exit 1
fi
echo "Detected cluster domain: $APPS_DOMAIN"

deployments=$(oc get deployments -n "$NAMESPACE" -o custom-columns=NAME:.metadata.name --no-headers | grep "^ssg-")

for dep in $deployments; do
  if [[ "$dep" == "$SKIP" ]]; then
    echo "SKIP: $dep (excluded)"
    continue
  fi

  dest_env=$(oc get deployment "$dep" -n "$NAMESPACE" \
    -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="DEST_ENV")].value}')

  echo "==> PATCH: $dep (dest_env=$dest_env)"

  # 1. Update image
  oc set image "deployment/$dep" -n "$NAMESPACE" "*=$IMAGE"

  # 2. Set env vars: polling interval, OIDC, monitoring
  oc set env "deployment/$dep" -n "$NAMESPACE" \
    "SLEEP_TIME=$SLEEP_TIME" \
    "OIDC_ISSUER_URL=$OIDC_ISSUER_URL" \
    "OIDC_AUDIENCE=$OIDC_AUDIENCE" \
    "KUBERNETESMONITOR=true" \
    "KUBERNETESREMOVE=true" \
    "KUBERNETES_ROLLOUT=true" \
    "RAVEN_DB_PATH=/data/raven-events.db" \
    "ARGOCD_SYNC_ENABLED=$ARGOCD_SYNC_ENABLED" \
    "ARGOCD_SERVER=$ARGOCD_SERVER" \
    "ARGOCD_APP_NAME=$ARGOCD_APP_NAME"

  # 2a. Per-raven PersistentVolumeClaim so the SQLite event store survives
  # restarts. Idempotent — PVC reused on subsequent runs.
  pvc="${dep}-events"
  if ! oc get pvc "$pvc" -n "$NAMESPACE" &>/dev/null; then
    cat <<EOF | oc apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: $pvc
  namespace: $NAMESPACE
  labels:
    app: $dep
spec:
  accessModes: ["ReadWriteOnce"]
  resources:
    requests:
      storage: 1Gi
EOF
    echo "  PVC created: $pvc"
  else
    echo "  PVC already exists: $pvc"
  fi

  # 2b. Mount the PVC at /data. Idempotent: oc set volume —overwrite replaces
  # any prior definition with the same name.
  oc set volume "deployment/$dep" -n "$NAMESPACE" \
    --add --name=raven-data --type=persistentVolumeClaim \
    --claim-name="$pvc" --mount-path=/data --overwrite

  # 2b. Mount ArgoCD bearer token from a K8s Secret (only if enabled and Secret exists).
  if [[ "$ARGOCD_SYNC_ENABLED" == "true" ]] && oc get secret "$ARGOCD_TOKEN_SECRET" -n "$NAMESPACE" &>/dev/null; then
    oc set env "deployment/$dep" -n "$NAMESPACE" \
      --from="secret/$ARGOCD_TOKEN_SECRET" --prefix=ARGOCD_AUTH_ --keys=token || true
    # Note: --prefix yields ARGOCD_AUTH_TOKEN from key 'token'.
  fi

  # 3. Set service account
  oc patch "deployment/$dep" -n "$NAMESPACE" --type=json \
    -p "[{\"op\":\"add\",\"path\":\"/spec/template/spec/serviceAccountName\",\"value\":\"$SA\"},{\"op\":\"add\",\"path\":\"/spec/template/spec/serviceAccount\",\"value\":\"$SA\"}]"

  # 4. Create Role + RoleBinding in target namespace (idempotent)
  if oc get namespace "$dest_env" &>/dev/null; then
    cat <<EOF | oc apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ssg-raven-role
  namespace: $dest_env
rules:
- apiGroups: ["*"]
  resources: ["secrets", "deployments", "statefulsets"]
  verbs: ["get", "watch", "list", "update", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ssg-raven-binding
  namespace: $dest_env
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: ssg-raven-role
subjects:
- kind: ServiceAccount
  name: $SA
  namespace: $NAMESPACE
EOF
    echo "  RBAC ensured in namespace $dest_env"
  else
    echo "  WARN: namespace $dest_env does not exist, skipping RBAC"
  fi

  # 5. Create Service (idempotent)
  if ! oc get svc "$dep" -n "$NAMESPACE" &>/dev/null; then
    cat <<EOF | oc apply -f -
apiVersion: v1
kind: Service
metadata:
  labels:
    app: $dep
  name: $dep
  namespace: $NAMESPACE
spec:
  ports:
  - port: 8080
    protocol: TCP
    targetPort: 8080
  selector:
    app: $dep
  type: ClusterIP
EOF
    echo "  Service created"
  else
    echo "  Service already exists"
  fi

  # 6. Create Route (idempotent)
  if ! oc get route "$dep" -n "$NAMESPACE" &>/dev/null; then
    cat <<EOF | oc apply -f -
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  labels:
    app: $dep
  name: $dep
  namespace: $NAMESPACE
spec:
  host: ${dep}-ssg.${APPS_DOMAIN}
  to:
    kind: Service
    name: $dep
    weight: 100
  port:
    targetPort: 8080
  tls:
    termination: edge
    insecureEdgeTerminationPolicy: Redirect
  wildcardPolicy: None
EOF
    echo "  Route created: ${dep}-ssg.${APPS_DOMAIN}"
  else
    echo "  Route already exists"
  fi

  # 7. Wait for rollout
  echo "  waiting for rollout..."
  oc rollout status "deployment/$dep" -n "$NAMESPACE" --timeout=120s
  echo "  done: $dep"
  echo "---"
done

echo "All deployments patched (except $SKIP)"
