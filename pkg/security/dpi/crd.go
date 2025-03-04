package dpi

// This file contains the CRD definitions for DPI-related resources
// These would be converted to actual Go API types using controller-gen
// For now, they are provided as a reference for the planned CRD structure

/*
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: dpiprofiles.security.fos1.io
spec:
  group: security.fos1.io
  names:
    kind: DPIProfile
    listKind: DPIProfileList
    plural: dpiprofiles
    singular: dpiprofile
    shortNames:
      - dpip
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
              properties:
                name:
                  type: string
                  description: "Name of the DPI profile"
                description:
                  type: string
                  description: "Description of the DPI profile"
                enabled:
                  type: boolean
                  description: "Whether the profile is enabled"
                  default: true
                inspectionDepth:
                  type: integer
                  minimum: 1
                  maximum: 10
                  description: "Depth of inspection (1-10, with 10 being deepest)"
                  default: 5
                applications:
                  type: array
                  items:
                    type: string
                  description: "Applications to detect"
                applicationCategories:
                  type: array
                  items:
                    type: string
                  description: "Application categories to detect"
                trafficClasses:
                  type: array
                  items:
                    type: object
                    required:
                      - name
                      - applications
                    properties:
                      name:
                        type: string
                        description: "Name of the traffic class"
                      applications:
                        type: array
                        items:
                          type: string
                        description: "Applications in this traffic class"
                      applicationCategories:
                        type: array
                        items:
                          type: string
                        description: "Application categories in this traffic class"
                      dscp:
                        type: integer
                        minimum: 0
                        maximum: 63
                        description: "DSCP value to set for matching traffic"
                customSignatures:
                  type: array
                  items:
                    type: object
                    required:
                      - name
                      - pattern
                    properties:
                      name:
                        type: string
                        description: "Name of the custom signature"
                      description:
                        type: string
                        description: "Description of the custom signature"
                      pattern:
                        type: string
                        description: "Pattern to match"
                      protocol:
                        type: string
                        enum: ["tcp", "udp", "any"]
                        description: "Protocol to match"
                        default: "any"
                      port:
                        type: string
                        description: "Port or port range to match"
                logging:
                  type: object
                  properties:
                    enabled:
                      type: boolean
                      description: "Whether to log detected applications"
                      default: true
                    logLevel:
                      type: string
                      enum: ["debug", "info", "warn", "error"]
                      description: "Log level for DPI events"
                      default: "info"
            status:
              type: object
              properties:
                detectedApplications:
                  type: object
                  additionalProperties:
                    type: integer
                  description: "Count of detected applications"
                lastUpdate:
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
  name: dpiflows.security.fos1.io
spec:
  group: security.fos1.io
  names:
    kind: DPIFlow
    listKind: DPIFlowList
    plural: dpiflows
    singular: dpiflow
    shortNames:
      - dpif
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
                - sourceNetwork
                - destinationNetwork
              properties:
                description:
                  type: string
                  description: "Description of the flow"
                enabled:
                  type: boolean
                  description: "Whether the flow is enabled"
                  default: true
                sourceNetwork:
                  type: string
                  description: "Source network or interface"
                destinationNetwork:
                  type: string
                  description: "Destination network or interface"
                profile:
                  type: string
                  description: "DPI profile to apply"
                bypassRules:
                  type: array
                  items:
                    type: object
                    required:
                      - match
                    properties:
                      match:
                        type: string
                        description: "Match criteria (e.g., ip, port, protocol)"
                      description:
                        type: string
                        description: "Description of the bypass rule"
            status:
              type: object
              properties:
                flowsProcessed:
                  type: integer
                  description: "Number of flows processed"
                bytesProcessed:
                  type: integer
                  description: "Number of bytes processed"
                lastUpdate:
                  type: string
                  format: date-time
                  description: "Timestamp of the last update"
      subresources:
        status: {}
*/