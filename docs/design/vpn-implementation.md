# VPN Implementation Design

1.  **Overview**

This document outlines the design for the VPN component in the Kubernetes-based Router/Firewall system. The VPN component will provide secure remote access and site-to-site connectivity, supporting multiple VPN protocols, authentication methods, and tight integration with other system components.

2.  **Design Goals**

*   Support multiple VPN protocols: WireGuard, OpenVPN, and IPsec.
*   Support both client and server modes for each protocol.
*   Provide secure authentication using username/password and certificates.
*   Enable policy-based filtering of traffic entering and exiting the VPN tunnel.
*   Allow selective routing of specific clients/networks over the VPN.
*   Integrate with the Threat Intelligence system to inform DPI inspection of VPN traffic.
*   Provide comprehensive monitoring and metrics for VPN connections.
*   Be configurable through Kubernetes CRDs.

3.  **System Architecture**

The VPN component will be managed by a `VPNManager` that orchestrates the different VPN protocol implementations. Each protocol will have its own handler responsible for configuring and managing the VPN tunnel.

*   3.1. Core Components
    *   **VPNManager:** The central component responsible for managing VPN configurations and coordinating the different protocol handlers.
    *   **Protocol Handlers:** Implementations for each supported VPN protocol (WireGuard, OpenVPN, IPsec). These handlers will be responsible for configuring and managing the VPN tunnels using the appropriate tools and libraries.
    *   **VPNConfig CRD:** Defines the desired state of a VPN connection, including the protocol, authentication method, and other settings.
    *   **VPNClient CRD:** Defines the client configuration for connecting to a VPN server.

*   3.2. Deployment Model

The VPN component will be deployed as a Kubernetes Deployment, with each protocol handler running as a separate container within the pod. This allows for easy scaling and management of the VPN service.

4.  **VPN Protocols**

The VPN component will support the following VPN protocols:

*   4.1. WireGuard

WireGuard is a modern VPN protocol that provides high performance and strong security. The **kernel module** will be the preferred implementation for WireGuard, leveraging its superior performance. The `wireguard-go` userspace implementation may be considered for specific use cases where kernel module support is unavailable or specific userspace customizations are required.

*   4.2. OpenVPN

OpenVPN is a widely used VPN protocol that supports a variety of encryption algorithms and authentication methods. It will be implemented using the `openvpn` command-line tool.

*   4.3. IPsec

IPsec is a suite of protocols that provides secure communication over IP networks. It will be implemented using the `strongSwan` VPN solution.

5.  **Authentication**

The VPN component will support the following authentication methods:

*   5.1. Username/Password Authentication

Username/password authentication will be implemented using PAM (Pluggable Authentication Modules).

*   5.2. Certificate-Based Authentication

Certificate-based authentication will be implemented using X.509 certificates.

6.  **Integration with Other Components**

The VPN component will integrate with the following components:

*   6.1. Policy Enforcement

    *   Cilium network policies will be used to filter traffic entering and exiting the VPN tunnel.
    *   Policies can be defined based on source/destination IP addresses, ports, protocols, and application metadata.
*   6.2. Routing

    *   Static and dynamic routes will be configured to direct traffic to and from the VPN tunnel.
    *   Policy-based routing will allow selective routing of specific clients/networks over the VPN.
*   6.3. Threat Intelligence

    *   The Threat Intelligence system will provide indicators of compromise (IoCs) to the DPI system for inspection of VPN traffic.
    *   Threat intelligence data will not directly affect VPN configuration.
*   6.4. DPI Stack

    *   The DPI stack will inspect VPN traffic to identify applications and extract metadata.
    *   DPI results will be used for policy-based filtering and routing of VPN traffic.

7.  **Custom Resource Definitions**

The VPN component will use the following CRDs:

*   7.1. VPNConfig CRD

    *   Defines the configuration for a VPN connection.

    ```yaml
    apiVersion: network.fos1.io/v1alpha1
    kind: VPNConfig
    metadata:
      name: my-vpn
    spec:
      protocol: wireguard
      serverMode: true
      clientMode: false
      interface: wg0
      listenPort: 51820
      privateKeySecret: wireguard-private-key
      peers:
        - publicKey: <peer_public_key>
          allowedIPs:
            - 10.0.0.2/32
      authentication:
        type: certificate
        caCertificateSecret: ca-cert
      policy:
        ingress: "allow-all"
        egress: "block-p2p"
      routingTable: "vpn-table"
    ```

*   7.2. VPNClient CRD

    *   Defines the client configuration for connecting to a VPN server.

    ```yaml
    apiVersion: network.fos1.io/v1alpha1
    kind: VPNClient
    metadata:
      name: my-vpn-client
    spec:
      serverAddress: <server_ip_address>
      serverPort: 51820
      protocol: wireguard
      authentication:
        type: certificate
        clientCertificateSecret: client-cert
        clientKeySecret: client-key
      allowedIPs:
        - 0.0.0.0/0
      dnsServers:
        - 1.1.1.1
        - 8.8.8.8