#!/usr/bin/env bash

set -e

if [[ -z "$CRC_REGISTRY" ]]; then
    CRC_REGISTRY="default-route-openshift-image-registry.apps-crc.testing"
fi

if [[ -z "$CRC_REGISTRY_PASSWORD" ]]; then
    echo "Environment Variable CRC_REGISTRY_PASSWORD is required to be able to push to test registry"
    exit 1
fi

GOOS=linux # set to darwin if in mac env

CGO_ENABLED=0 GOOS=$GOOS GOARCH=amd64 GO111MODULE=on go build -v -o "ssm" -ldflags="-s -w"

build_id=$(uuidgen)
project="davptest"

image_name=$CRC_REGISTRY/$project/ssm:$build_id

docker build -t $image_name .

docker login -u kubeadmin -p $CRC_REGISTRY_PASSWORD $CRC_REGISTRY
docker push $image_name