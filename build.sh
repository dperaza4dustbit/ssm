#!/usr/bin/env bash

set -e

if [[ -z "$IMAGE_REGISTRY" ]]; then
    IMAGE_REGISTRY="$(oc get route default-route -n openshift-image-registry --template='{{ .spec.host }}')"
fi

if [[ -z "$IMAGE_REGISTRY_PASSWORD" ]]; then
    IMAGE_REGISTRY_PASSWORD=$(oc whoami -t)
fi

GOOS=linux # set to darwin if in mac env

CGO_ENABLED=0 GOOS=$GOOS GOARCH=amd64 GO111MODULE=on go build -v -o "ssm" -ldflags="-s -w"

build_id="$(date +%s)"
project="davptest"

image_name=$IMAGE_REGISTRY/$project/ssm:$build_id

docker build -t $image_name .

docker login -u kubeadmin -p $IMAGE_REGISTRY_PASSWORD $IMAGE_REGISTRY
docker push $image_name