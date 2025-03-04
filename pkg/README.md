# Core Packages

This directory contains the core packages of the router/firewall distribution:

## Directory Structure

- `network/` - Network functionality (routing, interfaces, VLANs)
- `security/` - Security components (firewall, IDS, VPN)
- `dns/` - DNS service components (CoreDNS integration, AdGuard)
- `dhcp/` - DHCP service components (Kea integration, RADVD)

## Package Design Principles

1. **Interface-based design** - Use interfaces for dependency injection and testing
2. **Clear boundaries** - Packages should have well-defined responsibilities
3. **Minimal dependencies** - Avoid unnecessary dependencies between packages
4. **Comprehensive testing** - Each package should have thorough unit tests
5. **Documentation** - All exported types and functions should have documentation

## Adding New Packages

When adding a new package:

1. Create a clear README that explains the package's purpose
2. Create appropriate interfaces before implementations
3. Ensure proper error handling and logging
4. Add comprehensive unit tests
5. Update any related documentation