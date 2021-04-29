#!/usr/bin/env bash

set -e

# Setting OCP registry
oc patch configs.imageregistry.operator.openshift.io/cluster --patch '{"spec":{"defaultRoute":true}}' --type=merge
export IMAGE_REGISTRY=$(oc get route default-route -n openshift-image-registry --template='{{ .spec.host }}')
export IMAGE_PASWWORD=$(oc whoami -t)

oc new-project davptest

./build.sh

# After running build set ssm image stream lookup
oc set image-lookup ssm

oc create sa sa-with-anyuid
oc adm policy add-scc-to-user anyuid -z sa-with-anyuid

oc apply -f helm_repo.yaml
