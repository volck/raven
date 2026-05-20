#!/usr/bin/env bash
set -euo pipefail

export PATH="$PATH:$HOME/go/bin"
export KO_DOCKER_REPO="default-route-openshift-image-registry.apps.ocpdq02.norsk-tipping.no/ssg/ravenunstable"
export DOCKER_CONFIG="/run/user/21631/containers"

DEPLOYMENT="ssg-kubernetes-vault-test"
NAMESPACE="ssg"

echo "==> Building..."
ko build --bare --tags=latest --insecure-registry --sbom=none ./cmd/raven/

echo "==> Rolling out..."
oc rollout restart "deployment/$DEPLOYMENT" -n "$NAMESPACE"
oc rollout status "deployment/$DEPLOYMENT" -n "$NAMESPACE" --timeout=60s

echo "==> Done"
