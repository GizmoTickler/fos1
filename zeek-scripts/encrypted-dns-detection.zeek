##! Script for encrypted DNS detection
##! This script adds detection capabilities for DNSCrypt, DoT, and DoH

@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load policy/protocols/conn/vlan-logging
@load ./app-detection

module EncryptedDNSDetection;

export {
    # Define encrypted DNS types
    const DNS_DNSCRYPT = "dnscrypt" &redef;
    const DNS_DOT = "dns-over-tls" &redef;
    const DNS_DOH = "dns-over-https" &redef;
    
    # Add to the connection record
    redef record Conn::Info += {
        encrypted_dns: bool &default=F &log;
        encrypted_dns_type: string &optional &log;
    };
    
    # Known DoH providers
    global doh_providers: set[string] = {
        "dns.google",
        "cloudflare-dns.com",
        "dns.quad9.net",
        "dns.adguard.com",
        "doh.opendns.com",
        "dns.nextdns.io",
        "doh.cleanbrowsing.org",
        "dns.comss.one",
        "doh.dns.sb",
        "doh.powerdns.org",
        "doh.libredns.gr",
        "dns.digitale-gesellschaft.ch",
        "doh.securedns.eu",
        "dns.switch.ch",
        "dns.twnic.tw",
        "dns.containerpi.com",
        "doh.applied-privacy.net",
        "doh.xfinity.com",
        "dns.google.com",
        "mozilla.cloudflare-dns.com",
        "family.cloudflare-dns.com",
        "security.cloudflare-dns.com",
        "chrome.cloudflare-dns.com"
    };
    
    # Known DoT providers
    global dot_providers: set[string] = {
        "dns.google",
        "cloudflare-dns.com",
        "dns.quad9.net",
        "dns.adguard.com",
        "dns.nextdns.io",
        "dns.google.com",
        "one.one.one.one",
        "1dot1dot1dot1.cloudflare-dns.com",
        "dns9.quad9.net",
        "dns10.quad9.net",
        "dns11.quad9.net",
        "dns.switch.ch",
        "dot1.applied-privacy.net"
    };
    
    # Known DNSCrypt providers
    global dnscrypt_providers: set[string] = {
        "2.dnscrypt-cert.quad9.net",
        "2.dnscrypt-cert.opendns.com",
        "2.dnscrypt-cert.cloudflare.com",
        "2.dnscrypt-cert.adguard.com",
        "2.dnscrypt-cert.cleanbrowsing.org",
        "2.dnscrypt-cert.nextdns.io"
    };
    
    # DNSCrypt port
    const DNSCRYPT_PORT = 443/udp &redef;
    
    # DoT port
    const DOT_PORT = 853/tcp &redef;
}

# Helper function to set encrypted DNS info
function set_encrypted_dns_info(c: connection, dns_type: string) {
    c$conn$encrypted_dns = T;
    c$conn$encrypted_dns_type = dns_type;
    c$conn$service = dns_type;
    c$conn$app_category = "network-service";
    AppDetection::set_app_info(c, dns_type, "network-service");
}

###################
# DNS over HTTPS (DoH)
###################

# Detect DoH via HTTP headers
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "HOST") {
        if (value in doh_providers) {
            set_encrypted_dns_info(c, DNS_DOH);
        }
    }
    else if (name == "ACCEPT") {
        if (value == "application/dns-message" || value == "application/dns-json") {
            set_encrypted_dns_info(c, DNS_DOH);
        }
    }
    else if (name == "CONTENT-TYPE") {
        if (value == "application/dns-message" || value == "application/dns-json") {
            set_encrypted_dns_info(c, DNS_DOH);
        }
    }
}

# Detect DoH via URI
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    if (/\/dns-query/ in original_URI) {
        set_encrypted_dns_info(c, DNS_DOH);
    }
    else if (/\/resolve/ in original_URI && c$http?$host && c$http$host in doh_providers) {
        set_encrypted_dns_info(c, DNS_DOH);
    }
}

###################
# DNS over TLS (DoT)
###################

# Detect DoT via SSL/TLS
event ssl_established(c: connection) {
    if (c$id$resp_p == DOT_PORT) {
        set_encrypted_dns_info(c, DNS_DOT);
    }
    else if (c$ssl?$server_name && c$ssl$server_name in dot_providers) {
        set_encrypted_dns_info(c, DNS_DOT);
    }
}

###################
# DNSCrypt
###################

# Detect DNSCrypt via port and patterns
event connection_established(c: connection) {
    if (c$id$resp_p == DNSCRYPT_PORT) {
        # DNSCrypt often uses UDP port 443
        # This is a heuristic and may generate false positives
        # More accurate detection would require payload inspection
        set_encrypted_dns_info(c, DNS_DNSCRYPT);
    }
}

# Detect DNSCrypt via DNS queries for certificates
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    if (query in dnscrypt_providers) {
        set_encrypted_dns_info(c, DNS_DNSCRYPT);
    }
    else if (/dnscrypt-cert/ in query) {
        set_encrypted_dns_info(c, DNS_DNSCRYPT);
    }
}

# Log encrypted DNS detection
event connection_state_remove(c: connection) {
    if (c$conn?$encrypted_dns && c$conn$encrypted_dns) {
        local dns_type = c$conn?$encrypted_dns_type ? c$conn$encrypted_dns_type : "unknown";
        local msg = fmt("Detected encrypted DNS: %s from %s to %s", 
                        dns_type, c$id$orig_h, c$id$resp_h);
        print msg;
    }
}
