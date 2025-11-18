package firewall

// DEPRECATED: Use Cilium's network policy CRDs instead.
// This file is kept for reference but should not be used in new code.
//
// This file contains the CRD definitions for firewall rules and objects
// These would be converted to actual Go API types using controller-gen
// For now, they are provided as a reference for the planned CRD structure

/*
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: firewallrules.security.fos1.io
spec:
  group: security.fos1.io
  names:
    kind: FirewallRule
    listKind: FirewallRuleList
    plural: firewallrules
    singular: firewallrule
    shortNames:
      - fwr
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
                - action
              properties:
                name:
                  type: string
                  description: "Name of the firewall rule"
                description:
                  type: string
                  description: "Description of the firewall rule"
                enabled:
                  type: boolean
                  description: "Whether the rule is enabled"
                  default: true
                action:
                  type: string
                  enum: ["accept", "drop", "reject", "log"]
                  description: "Action to take for matching traffic"
                protocol:
                  type: string
                  enum: ["tcp", "udp", "icmp", "icmpv6", "any"]
                  description: "Protocol to match"
                  default: "any"
                sourceType:
                  type: string
                  enum: ["interface", "zone", "network", "ipset", "any"]
                  description: "Type of source matcher"
                  default: "any"
                source:
                  type: string
                  description: "Source to match (depends on sourceType)"
                sourcePort:
                  type: string
                  description: "Source port or port range (e.g., 1024-65535)"
                destinationType:
                  type: string
                  enum: ["interface", "zone", "network", "ipset", "any"]
                  description: "Type of destination matcher"
                  default: "any"
                destination:
                  type: string
                  description: "Destination to match (depends on destinationType)"
                destinationPort:
                  type: string
                  description: "Destination port or port range (e.g., 80,443)"
                ipVersion:
                  type: string
                  enum: ["ipv4", "ipv6", "both"]
                  description: "IP version to match"
                  default: "both"
                state:
                  type: object
                  description: "Connection state to match"
                  properties:
                    new:
                      type: boolean
                      description: "Match new connections"
                    established:
                      type: boolean
                      description: "Match established connections"
                    related:
                      type: boolean
                      description: "Match related connections"
                    invalid:
                      type: boolean
                      description: "Match invalid connections"
                application:
                  type: string
                  description: "Application name to match (DPI-based)"
                applicationCategory:
                  type: string
                  description: "Application category to match (DPI-based)"
                dscp:
                  type: integer
                  minimum: 0
                  maximum: 63
                  description: "DSCP value to match"
                logging:
                  type: boolean
                  description: "Whether to log matches"
                  default: false
                priority:
                  type: integer
                  description: "Priority of the rule (lower is higher priority)"
                  default: 100
                timeSchedule:
                  type: string
                  description: "Time schedule name to match"
            status:
              type: object
              properties:
                matchCount:
                  type: integer
                  description: "Number of matches for this rule"
                lastMatch:
                  type: string
                  format: date-time
                  description: "Timestamp of the last match"
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
  name: firewallipsets.security.fos1.io
spec:
  group: security.fos1.io
  names:
    kind: FirewallIPSet
    listKind: FirewallIPSetList
    plural: firewallipsets
    singular: firewallipset
    shortNames:
      - fwipset
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
                - entries
              properties:
                name:
                  type: string
                  description: "Name of the IP set"
                description:
                  type: string
                  description: "Description of the IP set"
                ipVersion:
                  type: string
                  enum: ["ipv4", "ipv6"]
                  description: "IP version of the set"
                  default: "ipv4"
                entries:
                  type: array
                  items:
                    type: string
                    pattern: "^([0-9]{1,3}\\.){3}[0-9]{1,3}(/[0-9]{1,2})?|([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(/[0-9]{1,3})?$"
                  description: "IP addresses or networks in the set"
            status:
              type: object
              properties:
                entryCount:
                  type: integer
                  description: "Number of entries in the set"
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
  name: firewallzones.security.fos1.io
spec:
  group: security.fos1.io
  names:
    kind: FirewallZone
    listKind: FirewallZoneList
    plural: firewallzones
    singular: firewallzone
    shortNames:
      - fwzone
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
                - interfaces
              properties:
                name:
                  type: string
                  description: "Name of the zone"
                description:
                  type: string
                  description: "Description of the zone"
                interfaces:
                  type: array
                  items:
                    type: string
                  description: "Interfaces in the zone"
                defaultAction:
                  type: string
                  enum: ["accept", "drop", "reject"]
                  description: "Default action for traffic from this zone"
                  default: "drop"
            status:
              type: object
              properties:
                interfaceCount:
                  type: integer
                  description: "Number of interfaces in the zone"
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
  name: applicationgroups.security.fos1.io
spec:
  group: security.fos1.io
  names:
    kind: ApplicationGroup
    listKind: ApplicationGroupList
    plural: applicationgroups
    singular: applicationgroup
    shortNames:
      - appgroup
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
                - applications
              properties:
                name:
                  type: string
                  description: "Name of the application group"
                description:
                  type: string
                  description: "Description of the application group"
                applications:
                  type: array
                  items:
                    type: string
                  description: "Applications in the group"
                categories:
                  type: array
                  items:
                    type: string
                  description: "Application categories in the group"
            status:
              type: object
              properties:
                applicationCount:
                  type: integer
                  description: "Number of applications in the group"
                lastUpdated:
                  type: string
                  format: date-time
                  description: "Timestamp of the last update"
      subresources:
        status: {}
*/
