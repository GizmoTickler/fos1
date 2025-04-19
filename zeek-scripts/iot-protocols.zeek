##! Script for IoT protocol detection
##! This script adds detection capabilities for IoT protocols

@load base/protocols/conn
@load base/protocols/http
@load base/protocols/dns
@load base/protocols/ssl
@load base/protocols/mqtt
@load policy/protocols/conn/vlan-logging
@load ./app-detection
@load ./iot-detection

module IoTProtocols;

export {
    # Define IoT protocol types
    const PROTO_MQTT = "mqtt" &redef;
    const PROTO_MQTT_SN = "mqtt-sn" &redef;
    const PROTO_COAP = "coap" &redef;
    const PROTO_AMQP = "amqp" &redef;
    const PROTO_ZIGBEE = "zigbee" &redef;
    const PROTO_ZWAVE = "zwave" &redef;
    const PROTO_THREAD = "thread" &redef;
    const PROTO_BACNET = "bacnet" &redef;
    const PROTO_MODBUS = "modbus" &redef;
    const PROTO_KNX = "knx" &redef;
    const PROTO_LORA = "lora" &redef;
    const PROTO_SIGFOX = "sigfox" &redef;
    const PROTO_WEAVE = "weave" &redef;
    const PROTO_HOMEKIT = "homekit" &redef;
    
    # Add to the connection record
    redef record Conn::Info += {
        iot_protocol: string &optional &log;
        iot_protocol_version: string &optional &log;
    };
    
    # Protocol ports
    const MQTT_PORTS: set[port] = {
        1883/tcp,  # MQTT
        8883/tcp,  # MQTT over TLS
        8884/tcp,  # MQTT over TLS (alternate)
        8885/tcp,  # MQTT over WebSockets
        8886/tcp   # MQTT over WebSockets with TLS
    };
    
    const MQTT_SN_PORTS: set[port] = {
        1883/udp,  # MQTT-SN
        1884/udp   # MQTT-SN (alternate)
    };
    
    const COAP_PORTS: set[port] = {
        5683/udp,  # CoAP
        5684/udp,  # CoAP over DTLS
        5685/udp,  # CoAP over WebSockets
        5686/udp,  # CoAP over WebSockets with TLS
        5687/udp,  # CoAP over TCP
        5688/udp,  # CoAP over TLS
        5689/udp   # CoAP over SMS
    };
    
    const AMQP_PORTS: set[port] = {
        5672/tcp,  # AMQP
        5671/tcp   # AMQP over TLS
    };
    
    const ZIGBEE_PORTS: set[port] = {
        44952/udp, # Zigbee IP
        44953/udp  # Zigbee IP (alternate)
    };
    
    const ZWAVE_PORTS: set[port] = {
        4123/udp   # Z-Wave
    };
    
    const THREAD_PORTS: set[port] = {
        19788/udp  # Thread
    };
    
    const BACNET_PORTS: set[port] = {
        47808/udp, # BACnet
        47809/udp  # BACnet (alternate)
    };
    
    const MODBUS_PORTS: set[port] = {
        502/tcp,   # Modbus TCP
        802/tcp    # Modbus TCP (alternate)
    };
    
    const KNX_PORTS: set[port] = {
        3671/udp,  # KNX
        3672/udp   # KNX (alternate)
    };
    
    const LORA_PORTS: set[port] = {
        1700/udp   # LoRaWAN
    };
    
    const HOMEKIT_PORTS: set[port] = {
        5353/udp   # HomeKit (mDNS)
    };
}

# Helper function to set IoT protocol info
function set_iot_protocol_info(c: connection, protocol: string, version: string = "") {
    c$conn$iot_protocol = protocol;
    if (version != "") {
        c$conn$iot_protocol_version = version;
    }
    c$conn$service = protocol;
    c$conn$app_category = AppDetection::CAT_IOT;
    AppDetection::set_app_info(c, protocol, AppDetection::CAT_IOT);
}

###################
# MQTT Detection
###################

# Detect MQTT via port
event connection_established(c: connection) {
    if (c$id$resp_p in MQTT_PORTS) {
        set_iot_protocol_info(c, PROTO_MQTT);
    }
    else if (c$id$resp_p in MQTT_SN_PORTS) {
        set_iot_protocol_info(c, PROTO_MQTT_SN);
    }
    else if (c$id$resp_p in COAP_PORTS) {
        set_iot_protocol_info(c, PROTO_COAP);
    }
    else if (c$id$resp_p in AMQP_PORTS) {
        set_iot_protocol_info(c, PROTO_AMQP);
    }
    else if (c$id$resp_p in ZIGBEE_PORTS) {
        set_iot_protocol_info(c, PROTO_ZIGBEE);
    }
    else if (c$id$resp_p in ZWAVE_PORTS) {
        set_iot_protocol_info(c, PROTO_ZWAVE);
    }
    else if (c$id$resp_p in THREAD_PORTS) {
        set_iot_protocol_info(c, PROTO_THREAD);
    }
    else if (c$id$resp_p in BACNET_PORTS) {
        set_iot_protocol_info(c, PROTO_BACNET);
    }
    else if (c$id$resp_p in MODBUS_PORTS) {
        set_iot_protocol_info(c, PROTO_MODBUS);
    }
    else if (c$id$resp_p in KNX_PORTS) {
        set_iot_protocol_info(c, PROTO_KNX);
    }
    else if (c$id$resp_p in LORA_PORTS) {
        set_iot_protocol_info(c, PROTO_LORA);
    }
    else if (c$id$resp_p in HOMEKIT_PORTS) {
        set_iot_protocol_info(c, PROTO_HOMEKIT);
    }
}

# Detect MQTT via protocol analyzer
event mqtt_connect(c: connection, msg: MQTT::ConnectMsg) {
    set_iot_protocol_info(c, PROTO_MQTT, msg$protocol_version);
    
    # Check for specific IoT devices in client ID
    IoTDetection::set_iot_info_from_mqtt(c, msg$client_id);
}

event mqtt_subscribe(c: connection, msg_id: count, topics: MQTT::SubscribeMsg) {
    set_iot_protocol_info(c, PROTO_MQTT);
    
    # Check for specific IoT devices in topics
    for (i in topics$topics) {
        local topic = topics$topics[i]$topic;
        IoTDetection::set_iot_info_from_mqtt_topic(c, topic);
    }
}

event mqtt_publish(c: connection, msg_id: count, msg: MQTT::PublishMsg) {
    set_iot_protocol_info(c, PROTO_MQTT);
    
    # Check for specific IoT devices in topic
    IoTDetection::set_iot_info_from_mqtt_topic(c, msg$topic);
}

###################
# CoAP Detection
###################

# CoAP detection via port is handled in connection_established

# Additional CoAP detection would require a custom analyzer
# This is a placeholder for future implementation

###################
# AMQP Detection
###################

# AMQP detection via port is handled in connection_established

# Additional AMQP detection would require a custom analyzer
# This is a placeholder for future implementation

###################
# Zigbee Detection
###################

# Zigbee detection via port is handled in connection_established

# Additional Zigbee detection would require a custom analyzer
# This is a placeholder for future implementation

###################
# Z-Wave Detection
###################

# Z-Wave detection via port is handled in connection_established

# Additional Z-Wave detection would require a custom analyzer
# This is a placeholder for future implementation

###################
# Thread Detection
###################

# Thread detection via port is handled in connection_established

# Additional Thread detection would require a custom analyzer
# This is a placeholder for future implementation

###################
# BACnet Detection
###################

# BACnet detection via port is handled in connection_established

# Additional BACnet detection would require a custom analyzer
# This is a placeholder for future implementation

###################
# Modbus Detection
###################

# Modbus detection via port is handled in connection_established

# Additional Modbus detection would require a custom analyzer
# This is a placeholder for future implementation

###################
# KNX Detection
###################

# KNX detection via port is handled in connection_established

# Additional KNX detection would require a custom analyzer
# This is a placeholder for future implementation

###################
# HomeKit Detection
###################

# HomeKit often uses mDNS for discovery
event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count) {
    if (c$id$resp_p == 5353/udp) {  # mDNS port
        if (msg?$queries) {
            for (i in msg$queries) {
                local query = msg$queries[i];
                if (/\.local/ in query$qname && /\._hap\._tcp/ in query$qname) {
                    set_iot_protocol_info(c, PROTO_HOMEKIT);
                }
            }
        }
    }
}
