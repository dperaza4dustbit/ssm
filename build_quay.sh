#!/usr/bin/env bash

set -e

if [[ -z "$IMAGE_REGISTRY" ]]; then
    IMAGE_REGISTRY="quay.io"
fi

GOOS=linux # set to darwin if in mac env

CGO_ENABLED=0 GOOS=$GOOS GOARCH=amd64 GO111MODULE=on go build -v -o "ssm" -ldflags="-s -w"

build_id="latest"
project="redhat-certification"

image_name=$IMAGE_REGISTRY/$project/ssm:$build_id

docker rmi $image_name
docker build -t $image_name .

docker push $image_name