#!/usr/bin/env bash

set -e

if [[ -z "$CRC_REGISTRY_PASSWORD" ]]; then
    echo "Environment Variable CRC_REGISTRY_PASSWORD is required to be able to push to test registry"
    exit 1
fi

GOOS=linux # pass darwin if in mac env

CGO_ENABLED=0 GOOS=$GOOS GOARCH=amd64 GO111MODULE=on go build -v -o "ssm" -ldflags="-s -w"

build_id=$(uuidgen)
project="davptest"

image_name=default-route-openshift-image-registry.apps-crc.testing/$project/ssm:$build_id

docker build -t $image_name .

docker login -u kubeadmin -p $CRC_REGISTRY_PASSWORD default-route-openshift-image-registry.apps-crc.testing
docker push $image_name