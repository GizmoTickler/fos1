##! Script for protocol-specific application detection
##! This script adds detection capabilities based on protocol analysis

@load base/protocols/conn
@load base/protocols/http
@load base/protocols/dns
@load base/protocols/ssl
@load base/protocols/ssh
@load base/protocols/smtp
@load base/protocols/ftp
@load base/protocols/sip
@load base/protocols/snmp
@load base/protocols/rdp
@load base/protocols/socks
@load base/protocols/smb
@load base/protocols/ntlm
@load base/protocols/ntp
@load base/protocols/dhcp
@load ./app-detection

module ProtocolDetection;

export {
    # Protocol to application mapping
    global protocol_app_map: table[string] of string = {
        "http"  => AppDetection::APP_HTTP,
        "https" => AppDetection::APP_HTTPS,
        "ssl"   => AppDetection::APP_HTTPS,
        "ssh"   => "ssh",
        "dns"   => "dns",
        "smtp"  => "smtp",
        "ftp"   => "ftp",
        "sip"   => "sip",
        "snmp"  => "snmp",
        "rdp"   => AppDetection::APP_RDP,
        "socks" => "socks",
        "smb"   => "smb",
        "ntlm"  => "ntlm",
        "ntp"   => "ntp",
        "dhcp"  => "dhcp",
        "mqtt"  => "mqtt",
        "coap"  => "coap",
        "modbus" => "modbus",
        "bacnet" => "bacnet",
        "telnet" => "telnet",
        "rtsp"  => "rtsp",
        "rtmp"  => "rtmp",
        "rtp"   => "rtp",
        "rtcp"  => "rtcp",
        "ssdp"  => "ssdp",
        "upnp"  => "upnp",
        "mdns"  => "mdns",
        "ldap"  => "ldap",
        "kerberos" => "kerberos",
        "radius" => "radius",
        "tftp"  => "tftp",
        "imap"  => "imap",
        "pop3"  => "pop3"
    };
    
    # Protocol to category mapping
    global protocol_category_map: table[string] of string = {
        "http"  => AppDetection::CAT_PRODUCTIVITY,
        "https" => AppDetection::CAT_PRODUCTIVITY,
        "ssl"   => AppDetection::CAT_PRODUCTIVITY,
        "ssh"   => AppDetection::CAT_PRODUCTIVITY,
        "dns"   => AppDetection::CAT_PRODUCTIVITY,
        "smtp"  => AppDetection::CAT_PRODUCTIVITY,
        "ftp"   => AppDetection::CAT_PRODUCTIVITY,
        "sip"   => AppDetection::CAT_CONFERENCING,
        "snmp"  => AppDetection::CAT_PRODUCTIVITY,
        "rdp"   => AppDetection::CAT_PRODUCTIVITY,
        "socks" => AppDetection::CAT_PRODUCTIVITY,
        "smb"   => AppDetection::CAT_PRODUCTIVITY,
        "ntlm"  => AppDetection::CAT_PRODUCTIVITY,
        "ntp"   => AppDetection::CAT_PRODUCTIVITY,
        "dhcp"  => AppDetection::CAT_PRODUCTIVITY,
        "mqtt"  => AppDetection::CAT_IOT,
        "coap"  => AppDetection::CAT_IOT,
        "modbus" => AppDetection::CAT_IOT,
        "bacnet" => AppDetection::CAT_IOT,
        "telnet" => AppDetection::CAT_PRODUCTIVITY,
        "rtsp"  => AppDetection::CAT_STREAMING,
        "rtmp"  => AppDetection::CAT_STREAMING,
        "rtp"   => AppDetection::CAT_STREAMING,
        "rtcp"  => AppDetection::CAT_STREAMING,
        "ssdp"  => AppDetection::CAT_IOT,
        "upnp"  => AppDetection::CAT_IOT,
        "mdns"  => AppDetection::CAT_PRODUCTIVITY,
        "ldap"  => AppDetection::CAT_PRODUCTIVITY,
        "kerberos" => AppDetection::CAT_PRODUCTIVITY,
        "radius" => AppDetection::CAT_PRODUCTIVITY,
        "tftp"  => AppDetection::CAT_PRODUCTIVITY,
        "imap"  => AppDetection::CAT_PRODUCTIVITY,
        "pop3"  => AppDetection::CAT_PRODUCTIVITY
    };
}

# Helper function to set application and category based on protocol
function set_app_info_from_protocol(c: connection, protocol: string) {
    # Check if we have an application mapping for this protocol
    if (protocol in protocol_app_map) {
        local app = protocol_app_map[protocol];
        
        # Set the application
        c$conn$service = app;
        
        # Set the category if available
        if (protocol in protocol_category_map) {
            c$conn$app_category = protocol_category_map[protocol];
        }
    }
}

# Apply protocol-based detection when a protocol is detected
event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count) {
    local protocol = Analyzer::name(atype);
    
    # Only apply if no service has been identified yet
    if (!c$conn?$service || c$conn$service == "") {
        set_app_info_from_protocol(c, protocol);
    }
}

# HTTP protocol detection
event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list) {
    # Set basic HTTP info
    set_app_info_from_protocol(c, "http");
    
    # Look for specific applications in headers
    for (i in hlist) {
        local name = hlist[i]$name;
        local value = hlist[i]$value;
        
        if (name == "HOST") {
            # Check for specific web applications
            if (/office365\.com/ in value || /microsoft365\.com/ in value) {
                AppDetection::set_app_info(c, "office365", AppDetection::CAT_PRODUCTIVITY);
            }
            else if (/google\.com\/docs/ in value || /docs\.google\.com/ in value) {
                AppDetection::set_app_info(c, "google-docs", AppDetection::CAT_PRODUCTIVITY);
            }
            else if (/dropbox\.com/ in value) {
                AppDetection::set_app_info(c, "dropbox", AppDetection::CAT_PRODUCTIVITY);
            }
            else if (/box\.com/ in value) {
                AppDetection::set_app_info(c, "box", AppDetection::CAT_PRODUCTIVITY);
            }
            else if (/onedrive\.com/ in value || /1drv\.ms/ in value) {
                AppDetection::set_app_info(c, "onedrive", AppDetection::CAT_PRODUCTIVITY);
            }
            else if (/sharepoint\.com/ in value) {
                AppDetection::set_app_info(c, "sharepoint", AppDetection::CAT_PRODUCTIVITY);
            }
            else if (/slack\.com/ in value) {
                AppDetection::set_app_info(c, AppDetection::APP_SLACK, AppDetection::CAT_PRODUCTIVITY);
            }
            else if (/zoom\.us/ in value) {
                AppDetection::set_app_info(c, AppDetection::APP_ZOOM, AppDetection::CAT_CONFERENCING);
            }
            else if (/teams\.microsoft\.com/ in value) {
                AppDetection::set_app_info(c, AppDetection::APP_TEAMS, AppDetection::CAT_CONFERENCING);
            }
        }
    }
}

# DNS protocol detection
event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count) {
    # Set basic DNS info
    set_app_info_from_protocol(c, "dns");
    
    # Look for specific applications in DNS queries
    if (msg?$queries) {
        for (i in msg$queries) {
            local query = msg$queries[i];
            local qname = query$qname;
            
            # Check for specific applications in DNS queries
            if (/netflix\.com/ in qname) {
                AppDetection::set_app_info(c, AppDetection::APP_NETFLIX, AppDetection::CAT_STREAMING);
            }
            else if (/youtube\.com/ in qname || /youtu\.be/ in qname) {
                AppDetection::set_app_info(c, AppDetection::APP_YOUTUBE, AppDetection::CAT_STREAMING);
            }
            else if (/spotify\.com/ in qname) {
                AppDetection::set_app_info(c, AppDetection::APP_SPOTIFY, AppDetection::CAT_STREAMING);
            }
            else if (/hulu\.com/ in qname) {
                AppDetection::set_app_info(c, AppDetection::APP_HULU, AppDetection::CAT_STREAMING);
            }
            else if (/disneyplus\.com/ in qname) {
                AppDetection::set_app_info(c, AppDetection::APP_DISNEY, AppDetection::CAT_STREAMING);
            }
            else if (/amazon\.com/ in qname && /video/ in qname) {
                AppDetection::set_app_info(c, AppDetection::APP_AMAZON, AppDetection::CAT_STREAMING);
            }
            else if (/primevideo\.com/ in qname) {
                AppDetection::set_app_info(c, AppDetection::APP_AMAZON, AppDetection::CAT_STREAMING);
            }
            else if (/hbomax\.com/ in qname) {
                AppDetection::set_app_info(c, AppDetection::APP_HBO, AppDetection::CAT_STREAMING);
            }
            else if (/twitch\.tv/ in qname) {
                AppDetection::set_app_info(c, AppDetection::APP_TWITCH, AppDetection::CAT_STREAMING);
            }
            else if (/facebook\.com/ in qname) {
                AppDetection::set_app_info(c, AppDetection::APP_FACEBOOK, AppDetection::CAT_SOCIAL);
            }
            else if (/instagram\.com/ in qname) {
                AppDetection::set_app_info(c, AppDetection::APP_INSTAGRAM, AppDetection::CAT_SOCIAL);
            }
            else if (/twitter\.com/ in qname) {
                AppDetection::set_app_info(c, AppDetection::APP_TWITTER, AppDetection::CAT_SOCIAL);
            }
            else if (/tiktok\.com/ in qname) {
                AppDetection::set_app_info(c, AppDetection::APP_TIKTOK, AppDetection::CAT_SOCIAL);
            }
            else if (/steampowered\.com/ in qname || /steamcommunity\.com/ in qname) {
                AppDetection::set_app_info(c, AppDetection::APP_STEAM, AppDetection::CAT_GAMING);
            }
            else if (/epicgames\.com/ in qname) {
                AppDetection::set_app_info(c, AppDetection::APP_EPIC, AppDetection::CAT_GAMING);
            }
            else if (/xbox\.com/ in qname || /xboxlive\.com/ in qname) {
                AppDetection::set_app_info(c, AppDetection::APP_XBOX, AppDetection::CAT_GAMING);
            }
            else if (/playstation\.com/ in qname || /playstation\.net/ in qname) {
                AppDetection::set_app_info(c, AppDetection::APP_PSN, AppDetection::CAT_GAMING);
            }
            else if (/nintendo\.com/ in qname) {
                AppDetection::set_app_info(c, AppDetection::APP_NINTENDO, AppDetection::CAT_GAMING);
            }
            else if (/roblox\.com/ in qname) {
                AppDetection::set_app_info(c, AppDetection::APP_ROBLOX, AppDetection::CAT_GAMING);
            }
            else if (/minecraft\.net/ in qname || /mojang\.com/ in qname) {
                AppDetection::set_app_info(c, AppDetection::APP_MINECRAFT, AppDetection::CAT_GAMING);
            }
        }
    }
}
