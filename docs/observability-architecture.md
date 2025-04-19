# Observability Stack Architecture

This document describes the observability stack architecture for the FOS1 project.

## Overview

The observability stack consists of the following components:

1. **Metrics Collection**: Prometheus for collecting and storing metrics
2. **Metrics Visualization**: Grafana for visualizing metrics
3. **Alerting**: Alertmanager for managing alerts
4. **Logging**: Elasticsearch, Fluentd, and Kibana (EFK) for collecting, storing, and visualizing logs

## Architecture Diagram

```
                                  ┌─────────────┐
                                  │             │
                                  │   Grafana   │
                                  │             │
                                  └──────┬──────┘
                                         │
                                         │
                                         ▼
┌─────────────┐                  ┌─────────────┐                  ┌─────────────┐
│             │                  │             │                  │             │
│ Alertmanager│◄─────────────────┤  Prometheus │◄─────────────────┤  Exporters  │
│             │                  │             │                  │             │
└─────────────┘                  └─────────────┘                  └─────────────┘
                                         │
                                         │
                                         ▼
                                  ┌─────────────┐
                                  │             │
                                  │  Alert Rules│
                                  │             │
                                  └─────────────┘


┌─────────────┐                  ┌─────────────┐                  ┌─────────────┐
│             │                  │             │                  │             │
│   Kibana    │◄─────────────────┤Elasticsearch│◄─────────────────┤   Fluentd   │
│             │                  │             │                  │             │
└─────────────┘                  └─────────────┘                  └─────────────┘
                                                                         ▲
                                                                         │
                                                                         │
                                                                  ┌─────────────┐
                                                                  │             │
                                                                  │  Log Sources │
                                                                  │             │
                                                                  └─────────────┘
```

## Components

### Prometheus

Prometheus is responsible for collecting and storing metrics from various sources. It scrapes metrics from exporters and stores them in a time-series database.

- **Deployment**: Single-instance deployment
- **Configuration**: ConfigMap with scrape configurations
- **Storage**: EmptyDir volume (for development, PersistentVolume for production)
- **Scrape Targets**: Kubernetes pods, nodes, services, and custom exporters

### Grafana

Grafana is used for visualizing metrics collected by Prometheus. It provides dashboards for various components of the system.

- **Deployment**: Single-instance deployment
- **Configuration**: ConfigMap with datasource and dashboard configurations
- **Storage**: EmptyDir volume (for development, PersistentVolume for production)
- **Dashboards**: Network, Security, System, and Traffic dashboards

### Alertmanager

Alertmanager is responsible for handling alerts sent by Prometheus. It deduplicates, groups, and routes alerts to the appropriate receiver.

- **Deployment**: Single-instance deployment
- **Configuration**: ConfigMap with routing and receiver configurations
- **Storage**: EmptyDir volume (for development, PersistentVolume for production)
- **Receivers**: Email, Slack, and PagerDuty

### Elasticsearch

Elasticsearch is used for storing and indexing logs collected by Fluentd. It provides a scalable and searchable log storage solution.

- **Deployment**: StatefulSet with a single replica (for development, multiple replicas for production)
- **Configuration**: ConfigMap with Elasticsearch configuration
- **Storage**: PersistentVolume for data
- **Indices**: Daily indices with retention policies

### Fluentd

Fluentd is responsible for collecting logs from various sources and forwarding them to Elasticsearch. It runs as a DaemonSet on each node.

- **Deployment**: DaemonSet
- **Configuration**: ConfigMap with Fluentd configuration
- **Sources**: Container logs, system logs, and application logs
- **Filters**: Kubernetes metadata, parsing, and transformation

### Kibana

Kibana is used for visualizing logs stored in Elasticsearch. It provides a web interface for searching and analyzing logs.

- **Deployment**: Single-instance deployment
- **Configuration**: ConfigMap with Kibana configuration
- **Storage**: None (stateless)
- **Dashboards**: Network, Security, and System dashboards

## Metrics Collection

The following metrics are collected by Prometheus:

1. **System Metrics**: CPU, memory, disk, and network usage
2. **Network Metrics**: Traffic, errors, drops, and latency
3. **Security Metrics**: Security events, firewall rule matches, and violations
4. **Application Metrics**: HTTP requests, gRPC calls, and custom metrics

## Log Collection

The following logs are collected by Fluentd:

1. **Container Logs**: Logs from all containers running in the cluster
2. **System Logs**: Logs from the operating system
3. **Application Logs**: Logs from applications running in the cluster
4. **Network Logs**: Logs from network components (routing, firewall, etc.)

## Alerting

Alerts are configured for the following conditions:

1. **System Alerts**: High CPU, memory, disk usage, and load
2. **Network Alerts**: High traffic, errors, drops, and latency
3. **Security Alerts**: Security events, firewall rule violations, and DPI engine status
4. **Application Alerts**: High error rates, latency, and service status

## Dashboards

The following dashboards are available in Grafana:

1. **Network Dashboard**: Network traffic, errors, drops, and latency
2. **Security Dashboard**: Security events, firewall rule matches, and violations
3. **System Dashboard**: CPU, memory, disk, and network usage
4. **Traffic Dashboard**: Traffic classes, bandwidth usage, and QoS metrics

## Scaling

The observability stack can be scaled in the following ways:

1. **Prometheus**: Increase resources, use remote storage, or deploy Thanos
2. **Elasticsearch**: Increase the number of replicas and shards
3. **Fluentd**: Increase resources for the DaemonSet
4. **Grafana**: Increase resources or deploy multiple instances behind a load balancer

## Security

The observability stack is secured in the following ways:

1. **Authentication**: Basic authentication for Prometheus, Alertmanager, and Kibana
2. **Authorization**: RBAC for Kubernetes resources
3. **Network Security**: Network policies to restrict traffic
4. **Data Security**: Encryption for data at rest and in transit

## Backup and Recovery

The following components require backup:

1. **Prometheus**: Backup the data directory
2. **Elasticsearch**: Backup the indices
3. **Grafana**: Backup the database

## Monitoring the Monitoring

The observability stack itself is monitored using the following metrics:

1. **Prometheus**: Scrape duration, sample count, and target status
2. **Elasticsearch**: Cluster health, index stats, and node stats
3. **Fluentd**: Buffer queue length, retry count, and error count
4. **Grafana**: HTTP request count, response time, and error count

## Conclusion

The observability stack provides comprehensive monitoring, logging, and alerting for the FOS1 project. It enables operators to quickly identify and troubleshoot issues in the system.
