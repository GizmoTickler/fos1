#!/bin/bash

# Setup script for FOS1 project
# This script initializes the project, setting up required dependencies

set -e

echo "Setting up FOS1 project..."

# Initialize Go modules if not already initialized
if [ ! -f go.mod ]; then
  echo "Initializing Go modules..."
  go mod init github.com/varuntirumala1/fos1
else
  echo "Go modules already initialized"
fi

# Add required dependencies
echo "Adding required dependencies..."
go get k8s.io/client-go@v0.26.1
go get k8s.io/apimachinery@v0.26.1
go get k8s.io/api@v0.26.1
go get k8s.io/klog/v2@v2.100.1
go get github.com/stretchr/testify@v1.8.4

# Create directory structure if not exists
mkdir -p pkg/apis/dns/v1alpha1
mkdir -p pkg/apis/dhcp/v1alpha1
mkdir -p pkg/client/clientset/versioned
mkdir -p pkg/client/informers/externalversions
mkdir -p pkg/client/listers
mkdir -p pkg/dns/manager
mkdir -p pkg/dns/coredns
mkdir -p pkg/dns/adguard
mkdir -p pkg/dns/mdns
mkdir -p pkg/dhcp/controller
mkdir -p pkg/dhcp/kea
mkdir -p test/integration
mkdir -p manifests/base/dns/crds
mkdir -p manifests/base/dhcp/crds
mkdir -p manifests/examples/dns
mkdir -p manifests/examples/dhcp

# Run go mod tidy to clean up dependencies
echo "Cleaning up dependencies..."
go mod tidy

echo "Setup complete!"
echo "You can now run 'make build' to build the project or 'make test' to run tests."
