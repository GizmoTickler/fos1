# Makefile for Kubernetes-based Router/Firewall

# Variables
GOPATH := $(shell go env GOPATH)
GOBIN := $(GOPATH)/bin
GO := go
GOFMT := gofmt
GOLINT := $(GOBIN)/golangci-lint
KUBECONFORM := $(GOBIN)/kubeconform
TALOSCTL := talosctl
KUBECTL := kubectl

# DPI Framework variables
REGISTRY ?= ghcr.io/varuntirumala1
IMAGE_NAME ?= dpi-framework
TAG ?= latest
PLATFORMS ?= linux/amd64,linux/arm64

# Build flags
BUILD_FLAGS := -v

# Test flags
TEST_FLAGS := -v -race

# Kubernetes context
KUBE_CONTEXT := default

# Default target
.PHONY: all
all: build test lint

# Setup the project
.PHONY: setup
setup:
	chmod +x scripts/setup.sh
	./scripts/setup.sh

# Build targets
.PHONY: build
build:
	$(GO) build $(BUILD_FLAGS) ./...

.PHONY: build-dns
build-dns:
	$(GO) build $(BUILD_FLAGS) ./pkg/dns/...

.PHONY: build-dhcp
build-dhcp:
	$(GO) build $(BUILD_FLAGS) ./pkg/dhcp/...

.PHONY: build-dpi
build-dpi:
	$(GO) build $(BUILD_FLAGS) -o bin/dpi-framework ./cmd/dpi-framework

# Test targets
.PHONY: test
test:
	$(GO) test $(TEST_FLAGS) ./...

.PHONY: test-dns
test-dns:
	$(GO) test $(TEST_FLAGS) ./pkg/dns/...

.PHONY: test-dhcp
test-dhcp:
	$(GO) test $(TEST_FLAGS) ./pkg/dhcp/...

.PHONY: test-dns-dhcp
test-dns-dhcp:
	$(GO) test $(TEST_FLAGS) ./pkg/dns/... ./pkg/dhcp/... ./test/integration/...

.PHONY: integration-test
integration-test:
	$(GO) test $(TEST_FLAGS) -tags=integration ./tests/integration/...

# Lint targets
.PHONY: lint
lint: lint-go lint-yaml

.PHONY: lint-go
lint-go:
	$(GOLINT) run ./...

.PHONY: lint-yaml
lint-yaml:
	find manifests -name "*.yaml" -o -name "*.yml" | xargs yamllint -c .yamllint.yml

.PHONY: lint-fix
lint-fix:
	$(GOLINT) run --fix ./...

# Format targets
.PHONY: fmt
fmt:
	$(GOFMT) -s -w .

# Kubernetes targets
.PHONY: manifests
manifests:
	mkdir -p dist/manifests
	kustomize build manifests/base > dist/manifests/all.yaml

# DPI Framework Kubernetes targets
.PHONY: dpi-manifests
dpi-manifests:
	mkdir -p dist/manifests/dpi
	cp deploy/kubernetes/*.yaml dist/manifests/dpi/

.PHONY: dpi-deploy
dpi-deploy:
	$(KUBECTL) apply -f deploy/kubernetes/zeek-deployment.yaml
	$(KUBECTL) apply -f deploy/kubernetes/dpi-framework-deployment.yaml
	$(KUBECTL) apply -f deploy/kubernetes/network-policies.yaml

.PHONY: dns-manifests
dns-manifests:
	mkdir -p dist/manifests/dns
	kustomize build manifests/base/dns > dist/manifests/dns/all.yaml

.PHONY: dhcp-manifests
dhcp-manifests:
	mkdir -p dist/manifests/dhcp
	kustomize build manifests/base/dhcp > dist/manifests/dhcp/all.yaml

.PHONY: validate-manifests
validate-manifests:
	find manifests -name "*.yaml" -o -name "*.yml" | xargs $(KUBECONFORM) -kubernetes-version 1.23.0

.PHONY: apply
apply:
	$(KUBECTL) --context $(KUBE_CONTEXT) apply -f dist/manifests/all.yaml

.PHONY: apply-dns
apply-dns:
	$(KUBECTL) --context $(KUBE_CONTEXT) apply -f dist/manifests/dns/all.yaml

.PHONY: apply-dhcp
apply-dhcp:
	$(KUBECTL) --context $(KUBE_CONTEXT) apply -f dist/manifests/dhcp/all.yaml

# Development environment
.PHONY: dev-env-up
dev-env-up:
	docker-compose -f dev/docker-compose.yml up -d

.PHONY: dev-env-down
dev-env-down:
	docker-compose -f dev/docker-compose.yml down

# Talos Linux targets
.PHONY: talos-config
talos-config:
	$(TALOSCTL) gen config router-fw https://router-fw-endpoint:6443 --output-dir config/talos

.PHONY: talos-apply
talos-apply:
	$(TALOSCTL) apply-config -n router-fw-endpoint -f config/talos/router-fw.yaml

# DPI Framework Talos targets
.PHONY: dpi-talos-extension
dpi-talos-extension:
	$(KUBECTL) apply -f deploy/talos/zeek-extension.yaml
	$(KUBECTL) apply -f deploy/talos/storage-config.yaml

.PHONY: dpi-talos-patch
dpi-talos-patch:
	$(TALOSCTL) patch machineconfig -n worker-1 -p @deploy/talos/machine-config-patch.yaml

# Clean targets
.PHONY: clean
clean:
	rm -rf dist/
	go clean -cache -testcache -modcache

# Install development tools
.PHONY: install-tools
install-tools:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOBIN) v1.51.2
	go install github.com/yannh/kubeconform/cmd/kubeconform@v0.6.2

# Docker image targets
.PHONY: docker-build
docker-build:
	docker build -t router-fw:latest .

# DPI Framework Docker image
.PHONY: dpi-docker-build
dpi-docker-build:
	docker buildx build --platform $(PLATFORMS) -t $(REGISTRY)/$(IMAGE_NAME):$(TAG) .

# Push DPI Framework Docker image
.PHONY: dpi-docker-push
dpi-docker-push:
	docker buildx build --platform $(PLATFORMS) -t $(REGISTRY)/$(IMAGE_NAME):$(TAG) --push .

# Help target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  setup              - Set up the project and install dependencies"
	@echo "  build              - Build all packages"
	@echo "  build-dns          - Build only DNS packages"
	@echo "  build-dhcp         - Build only DHCP packages"
	@echo "  build-dpi          - Build only DPI Framework"
	@echo "  test               - Run all tests"
	@echo "  test-dns           - Run DNS subsystem tests"
	@echo "  test-dhcp          - Run DHCP subsystem tests"
	@echo "  test-dns-dhcp      - Run both DNS and DHCP tests including integration"
	@echo "  integration-test   - Run integration tests"
	@echo "  lint               - Run all linters"
	@echo "  fmt                - Format Go code"
	@echo "  manifests          - Generate all Kubernetes manifests"
	@echo "  dns-manifests      - Generate DNS Kubernetes manifests"
	@echo "  dhcp-manifests     - Generate DHCP Kubernetes manifests"
	@echo "  dpi-manifests      - Generate DPI Framework Kubernetes manifests"
	@echo "  apply              - Apply manifests to Kubernetes cluster"
	@echo "  dpi-deploy         - Deploy DPI Framework to Kubernetes cluster"
	@echo "  dev-env-up         - Start development environment"
	@echo "  dev-env-down       - Stop development environment"
	@echo "  talos-config       - Generate Talos Linux configuration"
	@echo "  talos-apply        - Apply Talos Linux configuration"
	@echo "  dpi-talos-extension - Install Zeek extension for Talos Linux"
	@echo "  dpi-talos-patch    - Patch Talos machine config for Zeek"
	@echo "  clean              - Clean build artifacts"
	@echo "  install-tools      - Install development tools"
	@echo "  docker-build       - Build Docker image"
	@echo "  dpi-docker-build   - Build DPI Framework Docker image"
	@echo "  dpi-docker-push    - Push DPI Framework Docker image"