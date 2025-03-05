# Kea Database Backend Integration Design

## Overview

This document outlines the design for integrating the Kea DHCP server with a PostgreSQL database backend in the Kubernetes-based router/firewall system. This integration will provide persistent storage for DHCP leases, reservations, and configuration data across multiple VLAN segments.

## Design Goals

- Provide reliable persistence for DHCP lease information
- Support high availability and failover for DHCP services
- Enable lease history tracking for troubleshooting and auditing
- Support efficient querying of lease information
- Integrate cleanly with the Kubernetes environment
- Minimize performance impact on DHCP operations
- Support both DHCPv4 and DHCPv6 services

## Database Architecture

### Database Selection: PostgreSQL

PostgreSQL is selected as the database backend for Kea for the following reasons:

1. **Native Support**: Kea has first-class support for PostgreSQL
2. **Performance**: PostgreSQL offers good performance for the read/write patterns of DHCP services
3. **Kubernetes Integration**: Mature Kubernetes operators available for PostgreSQL
4. **Scalability**: Supports scaling for large networks with many leases
5. **Reliability**: Well-tested database with strong consistency guarantees

### Schema Design

The Kea schema will include the following key tables:

1. **dhcp4_lease**: Stores DHCPv4 lease information
   - lease_addr (IP address)
   - hwaddr (MAC address)
   - client_id
   - valid_lifetime
   - expire (timestamp)
   - subnet_id
   - hostname
   - state

2. **dhcp6_lease**: Stores DHCPv6 lease information
   - lease_type (NA/PD)
   - address/prefix
   - prefix_len
   - duid
   - hwaddr
   - valid_lifetime
   - expire (timestamp)
   - subnet_id
   - hostname
   - state

3. **dhcp4_options**: Stores DHCPv4 options associated with leases
4. **dhcp6_options**: Stores DHCPv6 options associated with leases
5. **lease_hwaddr_source**: Maps hardware address sources
6. **schema_version**: Tracks database schema version
7. **dhcp4_audit/dhcp6_audit**: Audit logs for lease changes (if enabled)

### Database Sizing

The database sizing will depend on the expected number of leases:

- **Base Storage**: ~50-100 bytes per lease record
- **Options Storage**: ~20-50 bytes per option
- **Audit Log**: ~100-200 bytes per lease event (if enabled)

For a typical deployment with up to 10,000 leases across all VLANs:
- Base storage requirement: ~1-2 MB
- With audit logs (30 days retention): ~50-100 MB

For larger deployments, storage requirements scale linearly with lease count.

## Kubernetes Integration

### PostgreSQL Deployment

PostgreSQL will be deployed using the CloudNativePG Kubernetes operator:

```yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: kea-database
  namespace: network
spec:
  instances: 3
  primaryUpdateStrategy: unsupervised
  
  # PostgreSQL configuration
  postgresql:
    parameters:
      max_connections: 100
      shared_buffers: 256MB
      effective_cache_size: 768MB
      maintenance_work_mem: 64MB
      checkpoint_completion_target: 0.9
      wal_buffers: 16MB
      default_statistics_target: 100
      random_page_cost: 1.1
      work_mem: 4MB
      
  # Storage configuration
  storage:
    size: 1Gi
    storageClass: standard
    
  # Backup configuration
  backup:
    retentionPolicy: 30d
    barmanObjectStore:
      destinationPath: s3://kea-backups/
      s3Credentials:
        accessKeyId:
          name: backup-creds
          key: ACCESS_KEY_ID
        secretAccessKey:
          name: backup-creds
          key: ACCESS_SECRET_KEY
      endpointURL: https://s3.example.com
      wal:
        compression: gzip
        maxParallel: 2
```

### Database Initialization

The database initialization will be performed using a Kubernetes Job that runs when the PostgreSQL cluster is ready:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: kea-db-init
  namespace: network
spec:
  template:
    spec:
      containers:
      - name: kea-db-init
        image: internetsystemsconsortium/kea:2.4.0
        command:
        - /bin/sh
        - -c
        - |
          # Wait for PostgreSQL to be ready
          until PGPASSWORD=$POSTGRES_PASSWORD psql -h kea-database-rw -U postgres -c '\q'; do
            echo "Waiting for PostgreSQL..."
            sleep 5
          done
          
          # Create database
          PGPASSWORD=$POSTGRES_PASSWORD psql -h kea-database-rw -U postgres -c "CREATE DATABASE kea"
          
          # Initialize schemas for DHCPv4 and DHCPv6
          kea-admin db-init pgsql -u postgres -p $POSTGRES_PASSWORD -h kea-database-rw -n kea -d dhcp4
          kea-admin db-init pgsql -u postgres -p $POSTGRES_PASSWORD -h kea-database-rw -n kea -d dhcp6
          
          echo "Database initialization completed successfully"
        env:
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: kea-database-app
              key: password
      restartPolicy: OnFailure
```

### Database Maintenance

Regular maintenance will be performed using CronJobs:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: kea-db-maintenance
  namespace: network
spec:
  schedule: "0 2 * * *"  # Run at 2 AM daily
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: kea-db-maintenance
            image: internetsystemsconsortium/kea:2.4.0
            command:
            - /bin/sh
            - -c
            - |
              # Vacuum database to reclaim space
              PGPASSWORD=$POSTGRES_PASSWORD psql -h kea-database-rw -U postgres -d kea -c "VACUUM FULL"
              
              # Remove expired audit logs (older than 30 days)
              PGPASSWORD=$POSTGRES_PASSWORD psql -h kea-database-rw -U postgres -d kea -c "DELETE FROM dhcp4_audit WHERE modification_ts < NOW() - INTERVAL '30 days'"
              PGPASSWORD=$POSTGRES_PASSWORD psql -h kea-database-rw -U postgres -d kea -c "DELETE FROM dhcp6_audit WHERE modification_ts < NOW() - INTERVAL '30 days'"
            env:
            - name: POSTGRES_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: kea-database-app
                  key: password
          restartPolicy: OnFailure
```

## Kea Configuration

### Kea Database Configuration

Both the DHCPv4 and DHCPv6 configurations will be updated to use PostgreSQL instead of the memfile backend:

```json
{
  "Dhcp4": {
    "lease-database": {
      "type": "postgresql",
      "name": "kea",
      "host": "kea-database-rw",
      "port": 5432,
      "user": "postgres",
      "password": "<password>",
      "max-reconnect-tries": 10,
      "reconnect-wait-time": 30000,
      "connect-timeout": 10
    },
    "hosts-database": {
      "type": "postgresql",
      "name": "kea",
      "host": "kea-database-rw",
      "port": 5432,
      "user": "postgres", 
      "password": "<password>",
      "max-reconnect-tries": 10,
      "reconnect-wait-time": 30000,
      "connect-timeout": 10
    },
    "hooks-libraries": [
      {
        "library": "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_lease_cmds.so"
      },
      {
        "library": "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_stat_cmds.so"
      }
    ],
    /* other DHCPv4 configuration elements */
  }
}
```

### Configuration Updates

The Kea configuration types in the codebase will be updated to support PostgreSQL:

```go
// LeaseDatabase configures where Kea stores lease information
type LeaseDatabase struct {
    Type               string `json:"type"`               // "memfile" or "postgresql"
    Name               string `json:"name"`               // Database name
    Host               string `json:"host,omitempty"`     // Database host
    Port               int    `json:"port,omitempty"`     // Database port
    User               string `json:"user,omitempty"`     // Database user
    Password           string `json:"password,omitempty"` // Database password
    MaxReconnectTries  int    `json:"max-reconnect-tries,omitempty"`  // Maximum reconnection attempts
    ReconnectWaitTime  int    `json:"reconnect-wait-time,omitempty"`  // Time between reconnection attempts (ms)
    ConnectTimeout     int    `json:"connect-timeout,omitempty"`      // Connection timeout (seconds)
    Persist            bool   `json:"persist,omitempty"`  // For memfile type only
}

// HostsDatabase configures where Kea stores host reservations
type HostsDatabase struct {
    Type               string `json:"type"`               // "postgresql"
    Name               string `json:"name"`               // Database name
    Host               string `json:"host,omitempty"`     // Database host
    Port               int    `json:"port,omitempty"`     // Database port
    User               string `json:"user,omitempty"`     // Database user
    Password           string `json:"password,omitempty"` // Database password
    MaxReconnectTries  int    `json:"max-reconnect-tries,omitempty"`  // Maximum reconnection attempts
    ReconnectWaitTime  int    `json:"reconnect-wait-time,omitempty"`  // Time between reconnection attempts (ms)
    ConnectTimeout     int    `json:"connect-timeout,omitempty"`      // Connection timeout (seconds)
}
```

### DHCPv4/DHCPv6 Service CRD Updates

The DHCPv4Service and DHCPv6Service CRDs will be updated to include database configuration:

```yaml
apiVersion: network.fos1.io/v1
kind: DHCPv4Service
metadata:
  name: vlan-10-dhcp
spec:
  vlanRef: vlan-10
  
  # DHCP settings
  leaseTime: 86400
  maxLeaseTime: 604800
  
  # Range of addresses to allocate dynamically
  range:
    start: 192.168.10.100
    end: 192.168.10.200
  
  # Database configuration
  database:
    enabled: true
    type: postgresql  # "postgresql" or "memfile"
    auditEnabled: true
    secretRef: kea-db-credentials  # Reference to K8s Secret
    # Other database config handled automatically
  
  # Other DHCP settings...
```

### Secret Management

Database credentials will be stored in a Kubernetes Secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: kea-db-credentials
  namespace: network
type: Opaque
data:
  username: cG9zdGdyZXM=  # base64 encoded "postgres"
  password: <base64-encoded-password>
```

## High Availability Design

For environments requiring high availability, Kea's HA capabilities will be enabled:

```json
{
  "Dhcp4": {
    "hooks-libraries": [
      {
        "library": "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_ha.so",
        "parameters": {
          "high-availability": [{
            "this-server-name": "server1",
            "mode": "hot-standby",
            "heartbeat-delay": 10000,
            "max-response-delay": 10000,
            "max-ack-delay": 5000,
            "max-unacked-clients": 5,
            "peers": [{
              "name": "server1",
              "url": "http://kea-dhcp-0.kea-dhcp.network.svc.cluster.local:8000/",
              "role": "primary",
              "auto-failover": true
            }, {
              "name": "server2",
              "url": "http://kea-dhcp-1.kea-dhcp.network.svc.cluster.local:8000/",
              "role": "standby",
              "auto-failover": true
            }]
          }]
        }
      }
    ]
  }
}
```

For HA deployments, the Kea DHCP service will be deployed as a StatefulSet instead of a Deployment to provide stable network identities:

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: kea-dhcp
  namespace: network
spec:
  serviceName: kea-dhcp
  replicas: 2
  # ... other StatefulSet configuration ...
```

## Performance Considerations

1. **Connection Pooling**: Configure appropriate connection pool size based on expected load
2. **Index Optimization**: Ensure indices on frequently queried fields
3. **Query Monitoring**: Set up query performance monitoring
4. **Database Resources**: Allocate appropriate CPU/memory resources based on network size
5. **Write Batching**: Configure Kea to batch database writes when possible

## Backup and Recovery

### Backup Strategy

1. **PostgreSQL Backups**: Automated using the CloudNativePG operator
2. **Point-in-time Recovery**: Enabled through WAL archiving
3. **Backup Retention**: 30 days of backups retained
4. **Backup Verification**: Regular automated validation of backups

### Recovery Procedures

1. **Database Restoration**:
   ```
   # For complete restoration:
   cnpg restore kea-database-restore \
     --cluster-name kea-database \
     --backup-id <backup-id>
   ```

2. **Point-in-time Recovery**:
   ```
   # For recovery to a specific point in time:
   cnpg restore kea-database-restore \
     --cluster-name kea-database \
     --backup-id <backup-id> \
     --recovery-target-time "2025-03-10 14:30:00+00"
   ```

3. **Disaster Recovery Plan**: Regular testing of recovery procedures

## Monitoring and Observability

### Key Metrics

1. **Database Performance**:
   - Query response times
   - Connection counts
   - Transaction rates
   - WAL generation rate

2. **DHCP Service Metrics**:
   - Lease allocation rate
   - Database operation latency
   - Failed database operations
   - Connection failures/reconnects

### Integration with Monitoring Stack

1. **Prometheus Metrics**:
   - PostgreSQL exporter for database metrics
   - Kea metrics via hooks-library

2. **Grafana Dashboards**:
   - Database performance dashboard
   - Lease utilization dashboard
   - Query performance dashboard

## Implementation Plan

### Phase 1: Basic PostgreSQL Integration
- Deploy PostgreSQL using CloudNativePG operator
- Update Kea configuration to use PostgreSQL
- Implement database initialization job
- Update CRDs to support database configuration

### Phase 2: High Availability Setup
- Configure Kea HA with PostgreSQL
- Implement StatefulSet deployment for Kea
- Set up connection redundancy

### Phase 3: Performance Optimization and Monitoring
- Configure monitoring for database performance
- Optimize schema and queries
- Implement performance testing

### Phase 4: Backup and Disaster Recovery
- Set up automated backups
- Implement and test recovery procedures
- Document disaster recovery process

## Code Examples

### Controller Implementation

```go
// ConfigureLeaseDatabases configures the lease databases for Kea
func (m *KeaManager) ConfigureLeaseDatabases(dhcp4Config *DHCPv4Config, dhcp6Config *DHCPv6Config, dbConfig *DatabaseConfig) error {
    // Configure DHCPv4 lease database
    dhcp4Config.Dhcp4.LeaseDatabase = LeaseDatabase{
        Type: dbConfig.Type,
    }
    
    // Configure DHCPv6 lease database
    dhcp6Config.Dhcp6.LeaseDatabase = LeaseDatabase{
        Type: dbConfig.Type,
    }
    
    // Configure based on database type
    if dbConfig.Type == "postgresql" {
        // Get credentials from secret
        dbCreds, err := m.getDBCredentials(dbConfig.SecretRef)
        if err != nil {
            return err
        }
        
        // Configure PostgreSQL settings
        pgConfig := PostgreSQLConfig{
            Name:              "kea",
            Host:              dbConfig.Host,
            Port:              dbConfig.Port,
            User:              dbCreds.Username,
            Password:          dbCreds.Password,
            MaxReconnectTries: 10,
            ReconnectWaitTime: 30000,
            ConnectTimeout:    10,
        }
        
        // Apply to both configs
        configurePgDatabase(&dhcp4Config.Dhcp4.LeaseDatabase, pgConfig)
        configurePgDatabase(&dhcp6Config.Dhcp6.LeaseDatabase, pgConfig)
        
        // Configure hosts database if needed
        if dbConfig.HostsEnabled {
            dhcp4Config.Dhcp4.HostsDatabase = HostsDatabase{
                Type: "postgresql",
            }
            configurePgDatabase(&dhcp4Config.Dhcp4.HostsDatabase, pgConfig)
            
            dhcp6Config.Dhcp6.HostsDatabase = HostsDatabase{
                Type: "postgresql",
            }
            configurePgDatabase(&dhcp6Config.Dhcp6.HostsDatabase, pgConfig)
        }
        
        // Add lease_cmds hook for lease management
        addHook(dhcp4Config, "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_lease_cmds.so", nil)
        addHook(dhcp6Config, "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_lease_cmds.so", nil)
        
        // Configure audit logging if enabled
        if dbConfig.AuditEnabled {
            auditParams := map[string]interface{}{
                "enable-audit": true,
                "audit-database-type": "postgresql",
                "audit-database-name": "kea",
                "audit-database-host": dbConfig.Host,
                "audit-database-port": dbConfig.Port,
                "audit-database-user": dbCreds.Username,
                "audit-database-password": dbCreds.Password,
            }
            addHook(dhcp4Config, "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_legal_log.so", auditParams)
            addHook(dhcp6Config, "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_legal_log.so", auditParams)
        }
    } else {
        // Configure memfile database
        dhcp4Config.Dhcp4.LeaseDatabase.Persist = true
        dhcp4Config.Dhcp4.LeaseDatabase.Name = "/var/lib/kea/dhcp4.leases"
        
        dhcp6Config.Dhcp6.LeaseDatabase.Persist = true
        dhcp6Config.Dhcp6.LeaseDatabase.Name = "/var/lib/kea/dhcp6.leases"
    }
    
    return nil
}

// Helper functions
func configurePgDatabase(db interface{}, config PostgreSQLConfig) {
    switch d := db.(type) {
    case *LeaseDatabase:
        d.Name = config.Name
        d.Host = config.Host
        d.Port = config.Port
        d.User = config.User
        d.Password = config.Password
        d.MaxReconnectTries = config.MaxReconnectTries
        d.ReconnectWaitTime = config.ReconnectWaitTime
        d.ConnectTimeout = config.ConnectTimeout
    case *HostsDatabase:
        d.Name = config.Name
        d.Host = config.Host
        d.Port = config.Port
        d.User = config.User
        d.Password = config.Password
        d.MaxReconnectTries = config.MaxReconnectTries
        d.ReconnectWaitTime = config.ReconnectWaitTime
        d.ConnectTimeout = config.ConnectTimeout
    }
}

func addHook(config interface{}, library string, params map[string]interface{}) {
    hook := HooksLibrary{
        Library:    library,
        Parameters: params,
    }
    
    switch c := config.(type) {
    case *DHCPv4Config:
        c.Dhcp4.HooksLibraries = append(c.Dhcp4.HooksLibraries, hook)
    case *DHCPv6Config:
        c.Dhcp6.HooksLibraries = append(c.Dhcp6.HooksLibraries, hook)
    }
}
```

## Conclusion

This design provides a comprehensive approach to implementing PostgreSQL as the database backend for Kea DHCP services in the Kubernetes-based router/firewall system. The design addresses all aspects of the integration including deployment, configuration, security, high availability, performance, and monitoring.

By implementing this design, the system will gain reliable persistence for DHCP lease information, enabling better troubleshooting, improved reliability, and support for high availability deployments.