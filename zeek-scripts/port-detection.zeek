##! Script for port-based application detection
##! This script adds detection capabilities based on port numbers

@load base/protocols/conn
@load ./app-detection

module PortDetection;

export {
    # Port to application mapping
    global port_app_map: table[port] of string = {
        # Web
        80/tcp  => AppDetection::APP_HTTP,
        443/tcp => AppDetection::APP_HTTPS,
        8080/tcp => AppDetection::APP_HTTP,
        8443/tcp => AppDetection::APP_HTTPS,
        
        # Email
        25/tcp  => "smtp",
        587/tcp => "smtp",
        465/tcp => "smtps",
        110/tcp => "pop3",
        995/tcp => "pop3s",
        143/tcp => "imap",
        993/tcp => "imaps",
        
        # File transfer
        21/tcp  => "ftp",
        22/tcp  => "ssh",
        
        # Remote access
        3389/tcp => AppDetection::APP_RDP,
        5900/tcp => "vnc",
        
        # Streaming
        1935/tcp => "rtmp",
        554/tcp  => "rtsp",
        
        # Messaging
        5222/tcp => "xmpp",
        5223/tcp => "xmpp",
        5269/tcp => "xmpp",
        5060/tcp => "sip",
        5061/tcp => "sips",
        
        # IoT
        1883/tcp => "mqtt",
        8883/tcp => "mqtts",
        5683/tcp => "coap",
        5684/tcp => "coaps",
        
        # Gaming
        27015/tcp => AppDetection::APP_STEAM,
        27016/tcp => AppDetection::APP_STEAM,
        27017/tcp => AppDetection::APP_STEAM,
        3074/tcp  => AppDetection::APP_XBOX,
        3075/tcp  => AppDetection::APP_XBOX,
        3076/tcp  => AppDetection::APP_XBOX,
        3478/tcp  => AppDetection::APP_PSN,
        3479/tcp  => AppDetection::APP_PSN,
        3480/tcp  => AppDetection::APP_PSN,
        
        # Databases
        3306/tcp => "mysql",
        5432/tcp => "postgres",
        1521/tcp => "oracle",
        1433/tcp => "mssql",
        27017/tcp => "mongodb",
        6379/tcp => "redis",
        
        # VPN
        1194/tcp => "openvpn",
        1194/udp => "openvpn",
        500/udp  => "ipsec",
        4500/udp => "ipsec-nat",
        1701/udp => "l2tp",
        1723/tcp => "pptp",
        
        # DNS
        53/tcp  => "dns",
        53/udp  => "dns",
        
        # DHCP
        67/udp  => "dhcp-server",
        68/udp  => "dhcp-client",
        
        # NTP
        123/udp => "ntp",
        
        # SNMP
        161/udp => "snmp",
        162/udp => "snmp-trap",
        
        # LDAP
        389/tcp => "ldap",
        636/tcp => "ldaps",
        
        # Kerberos
        88/tcp  => "kerberos",
        88/udp  => "kerberos",
        
        # SMB/CIFS
        445/tcp => "smb",
        139/tcp => "netbios",
        
        # RPC
        111/tcp => "rpc",
        111/udp => "rpc",
        
        # Printing
        631/tcp => "ipp",
        515/tcp => "printer",
        
        # Telnet
        23/tcp  => "telnet",
        
        # TFTP
        69/udp  => "tftp",
        
        # RADIUS
        1812/udp => "radius",
        1813/udp => "radius-accounting",
        
        # STUN
        3478/udp => "stun",
        
        # SIP
        5060/udp => "sip",
        5061/udp => "sips",
        
        # H.323
        1720/tcp => "h323",
        
        # RTCP
        5005/udp => "rtcp",
        
        # RTSP
        554/udp  => "rtsp",
        
        # IMAP
        143/udp  => "imap",
        
        # POP3
        110/udp  => "pop3"
    };
    
    # Port to category mapping
    global port_category_map: table[port] of string = {
        # Web
        80/tcp  => AppDetection::CAT_PRODUCTIVITY,
        443/tcp => AppDetection::CAT_PRODUCTIVITY,
        8080/tcp => AppDetection::CAT_PRODUCTIVITY,
        8443/tcp => AppDetection::CAT_PRODUCTIVITY,
        
        # Email
        25/tcp  => AppDetection::CAT_PRODUCTIVITY,
        587/tcp => AppDetection::CAT_PRODUCTIVITY,
        465/tcp => AppDetection::CAT_PRODUCTIVITY,
        110/tcp => AppDetection::CAT_PRODUCTIVITY,
        995/tcp => AppDetection::CAT_PRODUCTIVITY,
        143/tcp => AppDetection::CAT_PRODUCTIVITY,
        993/tcp => AppDetection::CAT_PRODUCTIVITY,
        
        # File transfer
        21/tcp  => AppDetection::CAT_PRODUCTIVITY,
        22/tcp  => AppDetection::CAT_PRODUCTIVITY,
        
        # Remote access
        3389/tcp => AppDetection::CAT_PRODUCTIVITY,
        5900/tcp => AppDetection::CAT_PRODUCTIVITY,
        
        # Streaming
        1935/tcp => AppDetection::CAT_STREAMING,
        554/tcp  => AppDetection::CAT_STREAMING,
        
        # Messaging
        5222/tcp => AppDetection::CAT_PRODUCTIVITY,
        5223/tcp => AppDetection::CAT_PRODUCTIVITY,
        5269/tcp => AppDetection::CAT_PRODUCTIVITY,
        5060/tcp => AppDetection::CAT_CONFERENCING,
        5061/tcp => AppDetection::CAT_CONFERENCING,
        
        # IoT
        1883/tcp => AppDetection::CAT_IOT,
        8883/tcp => AppDetection::CAT_IOT,
        5683/tcp => AppDetection::CAT_IOT,
        5684/tcp => AppDetection::CAT_IOT,
        
        # Gaming
        27015/tcp => AppDetection::CAT_GAMING,
        27016/tcp => AppDetection::CAT_GAMING,
        27017/tcp => AppDetection::CAT_GAMING,
        3074/tcp  => AppDetection::CAT_GAMING,
        3075/tcp  => AppDetection::CAT_GAMING,
        3076/tcp  => AppDetection::CAT_GAMING,
        3478/tcp  => AppDetection::CAT_GAMING,
        3479/tcp  => AppDetection::CAT_GAMING,
        3480/tcp  => AppDetection::CAT_GAMING
    };
}

# Helper function to set application and category based on port
function set_app_info_from_port(c: connection) {
    local dst_port = c$id$resp_p;
    local proto = get_port_transport_proto(dst_port);
    local port_num = port_to_count(dst_port);
    
    # Create the port with the correct protocol
    local p: port;
    if (proto == tcp) {
        p = port(port_num, tcp);
    } else if (proto == udp) {
        p = port(port_num, udp);
    } else {
        return;
    }
    
    # Check if we have an application mapping for this port
    if (p in port_app_map) {
        local app = port_app_map[p];
        
        # Set the application
        c$conn$service = app;
        
        # Set the category if available
        if (p in port_category_map) {
            c$conn$app_category = port_category_map[p];
        }
    }
}

# Apply port-based detection when a connection is established
event connection_established(c: connection) {
    # Only apply if no service has been identified yet
    if (!c$conn?$service || c$conn$service == "") {
        set_app_info_from_port(c);
    }
}

# Apply port-based detection when a connection is completed
event connection_state_remove(c: connection) {
    # Only apply if no service has been identified yet
    if (!c$conn?$service || c$conn$service == "") {
        set_app_info_from_port(c);
    }
}
