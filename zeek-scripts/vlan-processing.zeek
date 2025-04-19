##! Script for VLAN-specific processing
##! This script adds VLAN-aware processing to Zeek

@load base/protocols/conn
@load policy/protocols/conn/vlan-logging
@load ./app-detection

module VLANProcessing;

export {
    # Define VLAN configurations
    type VLANConfig: record {
        id: count;
        name: string;
        subnet: subnet;
        default_policy: string;
        applications: set[string];
    };
    
    # Global table of VLAN configurations
    global vlan_configs: table[count] of VLANConfig;
    
    # Initialize VLAN configurations
    global initialize_vlan_configs: function();
}

# Initialize VLAN configurations
function initialize_vlan_configs() {
    # IoT VLAN
    local iot_vlan: VLANConfig = [$id=10, 
                                 $name="iot", 
                                 $subnet=192.168.10.0/24, 
                                 $default_policy="restrict",
                                 $applications=set("mqtt", "http", "dns")];
    vlan_configs[10] = iot_vlan;
    
    # Media VLAN
    local media_vlan: VLANConfig = [$id=20, 
                                   $name="media", 
                                   $subnet=192.168.20.0/24, 
                                   $default_policy="allow",
                                   $applications=set("rtsp", "rtmp", "http", "https")];
    vlan_configs[20] = media_vlan;
    
    # Guest VLAN
    local guest_vlan: VLANConfig = [$id=30, 
                                   $name="guest", 
                                   $subnet=192.168.30.0/24, 
                                   $default_policy="deny",
                                   $applications=set("http", "https", "dns")];
    vlan_configs[30] = guest_vlan;
}

# Check if an application is allowed on a VLAN
function is_application_allowed(vlan_id: count, app: string): bool {
    if (vlan_id !in vlan_configs) {
        return T;  # If VLAN not configured, allow by default
    }
    
    local config = vlan_configs[vlan_id];
    
    # If no applications specified, allow all
    if (|config$applications| == 0) {
        return T;
    }
    
    # Check if application is in allowed list
    if (app in config$applications) {
        return T;
    }
    
    # Default policy
    if (config$default_policy == "allow") {
        return T;
    } else if (config$default_policy == "deny") {
        return F;
    } else {  # restrict
        return F;
    }
}

# Initialize VLAN configurations when Zeek starts
event zeek_init() {
    initialize_vlan_configs();
}

# Process connections with VLAN information
event connection_state_remove(c: connection) {
    if (!c?$vlan) {
        return;
    }
    
    local vlan_id = c$vlan;
    local app = "";
    
    # Get application if available
    if (c$conn?$app) {
        app = c$conn$app;
    } else if (c$conn?$service) {
        app = c$conn$service;
    }
    
    # Skip if no application identified
    if (app == "") {
        return;
    }
    
    # Check if application is allowed on this VLAN
    local allowed = is_application_allowed(vlan_id, app);
    
    # Log the result
    if (!allowed) {
        local msg = fmt("Application %s not allowed on VLAN %d", app, vlan_id);
        print msg;
        
        # In a real implementation, this would trigger an alert or block the traffic
    }
}
