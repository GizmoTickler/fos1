# Development Guide

This document provides instructions for setting up your development environment for the Kubernetes-based router/firewall project.

## Prerequisites

- Go 1.20 or later
- Docker and Docker Compose
- Kubernetes development tools (kubectl, kustomize)
- Talos Linux development tools (talosctl)

## Setting Up Your Development Environment

### 1. Install Required Tools

#### Go

Follow the [official Go installation instructions](https://golang.org/doc/install).

#### Docker and Docker Compose

Follow the [official Docker installation instructions](https://docs.docker.com/get-docker/).

#### Kubernetes Tools

```bash
# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/

# Install kustomize
curl -s "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh" | bash
sudo mv kustomize /usr/local/bin/
```

#### Talos Linux Tools

```bash
# Install talosctl
curl -Lo /usr/local/bin/talosctl https://github.com/talos-systems/talos/releases/latest/download/talosctl-$(uname -s | tr "[:upper:]" "[:lower:]")-amd64
chmod +x /usr/local/bin/talosctl
```

### 2. Clone the Repository

```bash
git clone https://github.com/varuntirumala1/fos1.git
cd fos1
```

### 3. Setup Virtual Testing Environment

For local development, we use a virtualized environment to simulate a network with multiple interfaces:

```bash
# Start the development environment
make dev-env-up

# To stop the environment
make dev-env-down
```

## Development Workflow

### Code Structure

- `cmd/` - Main application entry points
- `pkg/` - Core packages
- `internal/` - Internal packages not meant for external use
- `manifests/` - Kubernetes manifests for all components
- `config/` - Configuration templates
- `tests/` - Test suites

### Building Components

```bash
# Build all components
make build

# Build specific component
make build-<component>
```

### Running Tests

```bash
# Run all tests
make test

# Run specific test suite
make test-<component>

# Run integration tests
make integration-test
```

### Generate Kubernetes Manifests

```bash
# Generate all manifests
make manifests

# Apply manifests to development cluster
make apply
```

### Code Quality

Before submitting code, ensure it passes our quality checks:

```bash
# Run linters
make lint

# Fix automatic lint issues
make lint-fix

# Format code
make fmt
```

## Testing with Physical Hardware

For testing with physical hardware:

1. Prepare a machine with at least 2 network interfaces
2. Install Talos Linux using the ISO image or PXE boot
3. Apply our custom configuration using `talosctl apply-config`
4. Deploy services using `make deploy-hardware`

## Debugging

To debug services running in the environment:

```bash
# Get logs from a specific service
make logs-<service>

# Open a shell in a container
make exec-<service>

# View network traffic
make capture-<interface>
```

## Documentation

Documentation is written in Markdown and stored in the `docs/` directory. When making code changes, please update the relevant documentation.

## Creating a Pull Request

1. Create a new branch for your changes
2. Make your changes following our coding standards
3. Write or update tests to cover your changes
4. Run the full test suite to ensure everything passes
5. Submit a pull request with a clear description of the changes

See [CONTRIBUTING.md](../CONTRIBUTING.md) for more details on contributing to the project.