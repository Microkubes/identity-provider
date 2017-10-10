VERSION := $(shell git describe --tags --exact-match 2>/dev/null || echo latest)
DOCKERHUB_NAMESPACE ?= jormungandrk
IMAGE := ${DOCKERHUB_NAMESPACE}/identity-provider:${VERSION}

build:
	docker build -t ${IMAGE} .

push: build
	docker push ${IMAGE}

run: build
	docker run ${ARGS} ${IMAGE}
