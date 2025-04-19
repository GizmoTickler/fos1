##! Main script to load all custom scripts

# Load base protocols
@load base/protocols/conn
@load base/protocols/http
@load base/protocols/dns
@load base/protocols/ssl
@load base/protocols/ssh
@load base/protocols/smtp
@load base/protocols/ftp

# Load VLAN logging
@load policy/protocols/conn/vlan-logging

# Load custom scripts
@load ./app-detection
@load ./vlan-processing
@load ./iot-detection
@load ./port-detection
@load ./protocol-detection

# Print a message when scripts are loaded
event zeek_init() {
    print "Loaded custom DPI Framework scripts";
}
