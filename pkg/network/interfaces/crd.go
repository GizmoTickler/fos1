package interfaces

// This file contains the CRD definitions for network interfaces
// These would be converted to actual Go API types using controller-gen
// For now, they are provided as a reference for the planned CRD structure

/*
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: networkinterfaces.network.fos1.io
spec:
  group: network.fos1.io
  names:
    kind: NetworkInterface
    listKind: NetworkInterfaceList
    plural: networkinterfaces
    singular: networkinterface
    shortNames:
      - netif
  scope: Cluster
  versions:
    - name: v1alpha1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              required:
                - name
                - type
              properties:
                name:
                  type: string
                  description: "Name of the network interface"
                type:
                  type: string
                  enum: ["physical", "bridge", "vlan", "bond"]
                  description: "Type of network interface"
                parent:
                  type: string
                  description: "Parent interface name (required for vlan type)"
                vlanId:
                  type: integer
                  minimum: 1
                  maximum: 4094
                  description: "VLAN ID (required for vlan type)"
                addresses:
                  type: array
                  items:
                    type: string
                    pattern: "^([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}|([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}/[0-9]{1,3}$"
                  description: "IP addresses assigned to the interface in CIDR notation"
                dhcp:
                  type: boolean
                  description: "Whether to use DHCP for IPv4 on this interface"
                dhcp6:
                  type: boolean
                  description: "Whether to use DHCPv6 for IPv6 on this interface"
                slaac:
                  type: boolean
                  description: "Whether to use SLAAC for IPv6 on this interface"
                mtu:
                  type: integer
                  minimum: 68
                  maximum: 9000
                  description: "MTU for the interface"
                bridge:
                  type: object
                  description: "Bridge configuration (for bridge type)"
                  properties:
                    interfaces:
                      type: array
                      items:
                        type: string
                      description: "Interfaces to add to the bridge"
                    stp:
                      type: boolean
                      description: "Whether to enable STP"
                bond:
                  type: object
                  description: "Bond configuration (for bond type)"
                  properties:
                    interfaces:
                      type: array
                      items:
                        type: string
                      description: "Interfaces to add to the bond"
                    mode:
                      type: string
                      enum: ["balance-rr", "active-backup", "balance-xor", "broadcast", "802.3ad", "balance-tlb", "balance-alb"]
                      description: "Bond mode"
            status:
              type: object
              properties:
                operationalState:
                  type: string
                  enum: ["up", "down", "unknown"]
                  description: "Operational state of the interface"
                ipAddresses:
                  type: array
                  items:
                    type: string
                  description: "Current IP addresses assigned to the interface"
                macAddress:
                  type: string
                  description: "MAC address of the interface"
                mtu:
                  type: integer
                  description: "Current MTU of the interface"
                txBytes:
                  type: integer
                  description: "Bytes transmitted"
                rxBytes:
                  type: integer
                  description: "Bytes received"
                lastUpdated:
                  type: string
                  format: date-time
                  description: "Timestamp of the last update"
      subresources:
        status: {}
*/

/*
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: subnets.network.fos1.io
spec:
  group: network.fos1.io
  names:
    kind: Subnet
    listKind: SubnetList
    plural: subnets
    singular: subnet
  scope: Cluster
  versions:
    - name: v1alpha1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              required:
                - name
                - network
                - interface
              properties:
                name:
                  type: string
                  description: "Name of the subnet"
                network:
                  type: string
                  pattern: "^([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}|([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}/[0-9]{1,3}$"
                  description: "Network CIDR"
                interface:
                  type: string
                  description: "Interface this subnet is associated with"
                dhcp:
                  type: object
                  description: "DHCP configuration for this subnet"
                  properties:
                    enabled:
                      type: boolean
                      description: "Whether DHCP is enabled"
                    rangeStart:
                      type: string
                      pattern: "^([0-9]{1,3}\\.){3}[0-9]{1,3}$"
                      description: "Start of DHCP range"
                    rangeEnd:
                      type: string
                      pattern: "^([0-9]{1,3}\\.){3}[0-9]{1,3}$"
                      description: "End of DHCP range"
                    leaseTime:
                      type: integer
                      description: "Lease time in seconds"
                    options:
                      type: object
                      additionalProperties:
                        type: string
                      description: "DHCP options"
                dhcpv6:
                  type: object
                  description: "DHCPv6 configuration for this subnet"
                  properties:
                    enabled:
                      type: boolean
                      description: "Whether DHCPv6 is enabled"
                    mode:
                      type: string
                      enum: ["stateful", "stateless"]
                      description: "DHCPv6 mode"
                    prefixDelegation:
                      type: boolean
                      description: "Whether prefix delegation is enabled"
                    prefixLength:
                      type: integer
                      minimum: 1
                      maximum: 128
                      description: "Prefix length for delegation"
                routerAdvertisement:
                  type: object
                  description: "Router advertisement configuration for IPv6"
                  properties:
                    enabled:
                      type: boolean
                      description: "Whether router advertisements are enabled"
                    managed:
                      type: boolean
                      description: "Managed flag (M-bit)"
                    other:
                      type: boolean
                      description: "Other configuration flag (O-bit)"
                    prefixAutonomous:
                      type: boolean
                      description: "Autonomous flag (A-bit) for prefix"
                    prefixOnLink:
                      type: boolean
                      description: "On-link flag (L-bit) for prefix"
                    prefixValidLifetime:
                      type: integer
                      description: "Valid lifetime for prefix in seconds"
                    prefixPreferredLifetime:
                      type: integer
                      description: "Preferred lifetime for prefix in seconds"
                routing:
                  type: object
                  description: "Routing configuration for this subnet"
                  properties:
                    nat:
                      type: boolean
                      description: "Whether NAT is enabled for this subnet"
                    nat66:
                      type: boolean
                      description: "Whether NAT66 is enabled for this subnet (IPv6)"
                    defaultGateway:
                      type: string
                      pattern: "^([0-9]{1,3}\\.){3}[0-9]{1,3}$"
                      description: "Default gateway for this subnet"
                    defaultGatewayIpv6:
                      type: string
                      pattern: "^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
                      description: "Default gateway for IPv6"
                dns:
                  type: object
                  description: "DNS configuration for this subnet"
                  properties:
                    domain:
                      type: string
                      description: "DNS domain for this subnet"
                    servers:
                      type: array
                      items:
                        type: string
                        pattern: "^([0-9]{1,3}\\.){3}[0-9]{1,3}|([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
                      description: "DNS servers for this subnet"
                    searchDomains:
                      type: array
                      items:
                        type: string
                      description: "DNS search domains for this subnet"
                vlan:
                  type: object
                  description: "VLAN-specific configuration"
                  properties:
                    id:
                      type: integer
                      minimum: 1
                      maximum: 4094
                      description: "VLAN ID"
                    qos:
                      type: integer
                      minimum: 0
                      maximum: 7
                      description: "QoS priority (802.1p)"
            status:
              type: object
              properties:
                activeHosts:
                  type: integer
                  description: "Number of active hosts on this subnet"
                dhcpLeases:
                  type: integer
                  description: "Number of active DHCP leases"
                prefixDelegations:
                  type: integer
                  description: "Number of active prefix delegations"
                lastUpdated:
                  type: string
                  format: date-time
                  description: "Timestamp of the last update"
      subresources:
        status: {}
*/