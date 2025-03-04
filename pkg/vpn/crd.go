package vpn

// This file contains the CRD definitions for WireGuard VPN resources
// These would be converted to actual Go API types using controller-gen
// For now, they are provided as a reference for the planned CRD structure

/*
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: wiregaurdinterfaces.vpn.fos1.io
spec:
  group: vpn.fos1.io
  names:
    kind: WireGuardInterface
    listKind: WireGuardInterfaceList
    plural: wiregaurdinterfaces
    singular: wiregaurdinterface
    shortNames:
      - wgi
  scope: Namespaced
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
                - interfaceName
                - address
              properties:
                interfaceName:
                  type: string
                  pattern: "^[a-zA-Z0-9-_]+$"
                  description: "Name of the WireGuard interface"
                address:
                  type: string
                  pattern: "^([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$"
                  description: "CIDR notation address for the interface"
                listenPort:
                  type: integer
                  minimum: 1
                  maximum: 65535
                  description: "UDP port to listen on"
                privateKeySecret:
                  type: object
                  required:
                    - name
                    - key
                  properties:
                    name:
                      type: string
                      description: "Name of the secret containing the private key"
                    key:
                      type: string
                      description: "Key within the secret for the private key"
                postUp:
                  type: array
                  items:
                    type: string
                  description: "Commands to run after the interface is up"
                postDown:
                  type: array
                  items:
                    type: string
                  description: "Commands to run after the interface is down"
            status:
              type: object
              properties:
                active:
                  type: boolean
                  description: "Whether the interface is active"
                publicKey:
                  type: string
                  description: "Public key derived from the private key"
                message:
                  type: string
                  description: "Status message"
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
  name: wiregaurdpeers.vpn.fos1.io
spec:
  group: vpn.fos1.io
  names:
    kind: WireGuardPeer
    listKind: WireGuardPeerList
    plural: wiregaurdpeers
    singular: wiregaurdpeer
    shortNames:
      - wgp
  scope: Namespaced
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
                - interfaceRef
                - publicKey
                - allowedIPs
              properties:
                interfaceRef:
                  type: string
                  description: "Name of the WireGuardInterface resource"
                publicKey:
                  type: string
                  description: "Public key of the peer"
                presharedKeySecret:
                  type: object
                  required:
                    - name
                    - key
                  properties:
                    name:
                      type: string
                      description: "Name of the secret containing the preshared key"
                    key:
                      type: string
                      description: "Key within the secret for the preshared key"
                endpoint:
                  type: string
                  pattern: "^([0-9]{1,3}\\.){3}[0-9]{1,3}:[0-9]{1,5}$"
                  description: "Endpoint address:port of the peer"
                allowedIPs:
                  type: array
                  items:
                    type: string
                    pattern: "^([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$"
                  description: "Allowed IPs for the peer in CIDR notation"
                persistentKeepalive:
                  type: integer
                  minimum: 0
                  maximum: 65535
                  description: "Persistent keepalive interval in seconds"
            status:
              type: object
              properties:
                active:
                  type: boolean
                  description: "Whether the peer is active"
                connected:
                  type: boolean
                  description: "Whether the peer is currently connected"
                latestHandshake:
                  type: string
                  format: date-time
                  description: "Timestamp of the latest handshake"
                transferRx:
                  type: integer
                  description: "Bytes received from the peer"
                transferTx:
                  type: integer
                  description: "Bytes transmitted to the peer"
                message:
                  type: string
                  description: "Status message"
                lastUpdated:
                  type: string
                  format: date-time
                  description: "Timestamp of the last update"
      subresources:
        status: {}
*/