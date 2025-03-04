package qos

// This file contains the CRD definitions for QoS resources
// These would be converted to actual Go API types using controller-gen
// For now, they are provided as a reference for the planned CRD structure

/*
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: qosprofiles.network.fos1.io
spec:
  group: network.fos1.io
  names:
    kind: QoSProfile
    listKind: QoSProfileList
    plural: qosprofiles
    singular: qosprofile
    shortNames:
      - qosp
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
                - interface
              properties:
                interface:
                  type: string
                  description: "Interface to apply QoS to"
                uploadBandwidth:
                  type: string
                  description: "Upload bandwidth limit (e.g., 10Mbit)"
                downloadBandwidth:
                  type: string
                  description: "Download bandwidth limit (e.g., 100Mbit)"
                defaultClass:
                  type: string
                  description: "Default traffic class for unclassified traffic"
                  default: "default"
                classes:
                  type: array
                  items:
                    type: object
                    required:
                      - name
                      - priority
                    properties:
                      name:
                        type: string
                        description: "Name of the traffic class"
                      priority:
                        type: integer
                        minimum: 1
                        maximum: 7
                        description: "Priority of the traffic class (1-7, with 1 being highest)"
                      minBandwidth:
                        type: string
                        description: "Minimum guaranteed bandwidth (e.g., 1Mbit, 10%)"
                      maxBandwidth:
                        type: string
                        description: "Maximum bandwidth limit (e.g., 5Mbit, 20%)"
                      burst:
                        type: string
                        description: "Burst size (e.g., 15kb)"
                      dscp:
                        type: integer
                        minimum: 0
                        maximum: 63
                        description: "DSCP value for this class"
                      applications:
                        type: array
                        items:
                          type: string
                        description: "Applications to match for this class"
                      applicationCategories:
                        type: array
                        items:
                          type: string
                        description: "Application categories to match for this class"
                      sourceAddresses:
                        type: array
                        items:
                          type: string
                        description: "Source addresses to match for this class"
                      destinationAddresses:
                        type: array
                        items:
                          type: string
                        description: "Destination addresses to match for this class"
                      sourcePort:
                        type: string
                        description: "Source port or port range to match"
                      destinationPort:
                        type: string
                        description: "Destination port or port range to match"
                      protocol:
                        type: string
                        enum: ["tcp", "udp", "icmp", "any"]
                        description: "Protocol to match"
                        default: "any"
            status:
              type: object
              properties:
                actualUploadBandwidth:
                  type: string
                  description: "Actual configured upload bandwidth"
                actualDownloadBandwidth:
                  type: string
                  description: "Actual configured download bandwidth"
                classStatistics:
                  type: object
                  additionalProperties:
                    type: object
                    properties:
                      packets:
                        type: integer
                        description: "Number of packets processed"
                      bytes:
                        type: integer
                        description: "Number of bytes processed"
                      drops:
                        type: integer
                        description: "Number of packets dropped"
                lastUpdated:
                  type: string
                  format: date-time
                  description: "Timestamp of the last update"
      subresources:
        status: {}
*/