# Dashboard User Guide

This document provides a guide to using the dashboards in the FOS1 observability stack.

## Overview

The FOS1 observability stack includes the following dashboards:

1. **Network Dashboard**: Network traffic, errors, drops, and latency
2. **Security Dashboard**: Security events, firewall rule matches, and violations
3. **System Dashboard**: CPU, memory, disk, and network usage
4. **Traffic Dashboard**: Traffic classes, bandwidth usage, and QoS metrics

## Accessing Dashboards

All dashboards are accessible through the Grafana UI. To access the dashboards:

1. Open a web browser and navigate to the Grafana URL (e.g., `http://grafana.example.com`)
2. Log in with your credentials
3. Click on the "Dashboards" menu in the left sidebar
4. Select the dashboard you want to view

## Network Dashboard

The Network Dashboard provides an overview of network traffic, errors, drops, and latency.

### Panels

1. **Network Traffic by Interface**: Shows the incoming and outgoing traffic for each network interface
2. **Packet Rate by Interface**: Shows the packet rate for each network interface
3. **Traffic Class Rates**: Shows the traffic rate for each traffic class
4. **Traffic Class Utilization**: Shows the utilization percentage for each traffic class
5. **Interface Errors**: Shows the error rate for each network interface
6. **Interface Drops**: Shows the drop rate for each network interface

### Use Cases

- **Monitoring Network Traffic**: Use the "Network Traffic by Interface" panel to monitor the traffic on each interface
- **Identifying Network Issues**: Use the "Interface Errors" and "Interface Drops" panels to identify network issues
- **Monitoring QoS**: Use the "Traffic Class Rates" and "Traffic Class Utilization" panels to monitor QoS

## Security Dashboard

The Security Dashboard provides an overview of security events, firewall rule matches, and violations.

### Panels

1. **Critical Security Events**: Shows the number of critical security events
2. **High Security Events**: Shows the number of high security events
3. **Medium Security Events**: Shows the number of medium security events
4. **Low Security Events**: Shows the number of low security events
5. **Security Events by Type**: Shows the rate of security events by type
6. **Security Events by Severity**: Shows the rate of security events by severity
7. **Firewall Rule Matches by Action**: Shows the rate of firewall rule matches by action
8. **Firewall Rule Violations**: Shows the rate of firewall rule violations

### Use Cases

- **Monitoring Security Events**: Use the security event panels to monitor security events
- **Identifying Security Issues**: Use the "Security Events by Type" and "Security Events by Severity" panels to identify security issues
- **Monitoring Firewall Rules**: Use the "Firewall Rule Matches by Action" and "Firewall Rule Violations" panels to monitor firewall rules

## System Dashboard

The System Dashboard provides an overview of CPU, memory, disk, and network usage.

### Panels

1. **CPU Usage**: Shows the CPU usage for each node
2. **Memory Usage**: Shows the memory usage for each node
3. **Disk Usage**: Shows the disk usage for each node
4. **Network Traffic**: Shows the network traffic for each node
5. **System Load**: Shows the system load for each node
6. **Disk I/O**: Shows the disk I/O for each node

### Use Cases

- **Monitoring System Resources**: Use the CPU, memory, and disk usage panels to monitor system resources
- **Identifying Resource Issues**: Use the system load and disk I/O panels to identify resource issues
- **Capacity Planning**: Use the resource usage panels to plan for capacity

## Traffic Dashboard

The Traffic Dashboard provides an overview of traffic classes, bandwidth usage, and QoS metrics.

### Panels

1. **Interface Bandwidth Usage**: Shows the bandwidth usage for each interface
2. **Interface Utilization**: Shows the utilization percentage for each interface
3. **Traffic Class Rates**: Shows the traffic rate for each traffic class
4. **Traffic Class Utilization**: Shows the utilization percentage for each traffic class
5. **Traffic Class Drops**: Shows the drop rate for each traffic class
6. **Interface Errors**: Shows the error rate for each interface

### Use Cases

- **Monitoring Bandwidth Usage**: Use the "Interface Bandwidth Usage" and "Interface Utilization" panels to monitor bandwidth usage
- **Monitoring QoS**: Use the "Traffic Class Rates" and "Traffic Class Utilization" panels to monitor QoS
- **Identifying QoS Issues**: Use the "Traffic Class Drops" panel to identify QoS issues

## Time Range Selection

All dashboards support time range selection. To change the time range:

1. Click on the time range selector in the top-right corner of the dashboard
2. Select a predefined time range (e.g., "Last 1 hour", "Last 6 hours", "Last 24 hours")
3. Or, select "Custom time range" to specify a custom time range

## Refreshing Dashboards

All dashboards automatically refresh every 5 seconds. To manually refresh a dashboard:

1. Click on the refresh button in the top-right corner of the dashboard
2. Or, press F5 to refresh the entire page

## Exporting Data

To export data from a dashboard:

1. Click on the panel title
2. Select "More..." from the dropdown menu
3. Select "Export CSV" to export the data as a CSV file
4. Or, select "Export Panel JSON" to export the panel configuration as a JSON file

## Creating Alerts

To create an alert from a dashboard panel:

1. Click on the panel title
2. Select "Edit" from the dropdown menu
3. Click on the "Alert" tab
4. Configure the alert conditions, evaluation interval, and notifications
5. Click "Save" to save the alert

## Troubleshooting

If you encounter issues with the dashboards:

1. **Dashboard Not Loading**: Check if Grafana is running and accessible
2. **No Data**: Check if Prometheus is running and collecting metrics
3. **Incomplete Data**: Check if the time range is set correctly
4. **Slow Dashboard**: Try reducing the time range or the number of panels

## Conclusion

The dashboards in the FOS1 observability stack provide comprehensive monitoring of network, security, system, and traffic metrics. Use these dashboards to monitor the health and performance of your FOS1 deployment.
