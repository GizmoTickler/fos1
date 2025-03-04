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

# Build flags
BUILD_FLAGS := -v

# Test flags
TEST_FLAGS := -v -race

# Kubernetes context
KUBE_CONTEXT := default

# Default target
.PHONY: all
all: build test lint

# Build targets
.PHONY: build
build:
	$(GO) build $(BUILD_FLAGS) ./...

# Test targets
.PHONY: test
test:
	$(GO) test $(TEST_FLAGS) ./...

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

.PHONY: validate-manifests
validate-manifests:
	find manifests -name "*.yaml" -o -name "*.yml" | xargs $(KUBECONFORM) -kubernetes-version 1.23.0

.PHONY: apply
apply:
	$(KUBECTL) --context $(KUBE_CONTEXT) apply -f dist/manifests/all.yaml

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

# Help target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build            - Build all packages"
	@echo "  test             - Run all tests"
	@echo "  integration-test - Run integration tests"
	@echo "  lint             - Run all linters"
	@echo "  fmt              - Format Go code"
	@echo "  manifests        - Generate Kubernetes manifests"
	@echo "  apply            - Apply manifests to Kubernetes cluster"
	@echo "  dev-env-up       - Start development environment"
	@echo "  dev-env-down     - Stop development environment"
	@echo "  talos-config     - Generate Talos Linux configuration"
	@echo "  talos-apply      - Apply Talos Linux configuration"
	@echo "  clean            - Clean build artifacts"
	@echo "  install-tools    - Install development tools"
	@echo "  docker-build     - Build Docker image"