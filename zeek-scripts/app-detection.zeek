##! Script for enhanced application detection
##! This script adds additional application detection capabilities to Zeek

@load base/protocols/conn
@load base/protocols/http
@load base/protocols/dns
@load base/protocols/ssl
@load base/protocols/ssh
@load policy/protocols/conn/vlan-logging

module AppDetection;

export {
    # Define new application types
    const APP_NETFLIX = "netflix" &redef;
    const APP_YOUTUBE = "youtube" &redef;
    const APP_ZOOM = "zoom" &redef;
    const APP_PLEX = "plex" &redef;
    const APP_SPOTIFY = "spotify" &redef;
    const APP_HULU = "hulu" &redef;
    const APP_AMAZON = "amazon-video" &redef;
    const APP_DISNEY = "disney-plus" &redef;
    
    # Add to the connection record
    redef record Conn::Info += {
        app: string &optional &log;
        vlan: int &optional &log;
    };
}

# Netflix detection
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "HOST" && /netflix\.com/ in value) {
        c$conn$app = APP_NETFLIX;
    }
}

# YouTube detection
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "HOST" && /youtube\.com/ in value) {
        c$conn$app = APP_YOUTUBE;
    }
    else if (name == "HOST" && /youtu\.be/ in value) {
        c$conn$app = APP_YOUTUBE;
    }
}

# Zoom detection
event ssl_established(c: connection) {
    if (c$ssl?$server_name && /zoom\.us/ in c$ssl$server_name) {
        c$conn$app = APP_ZOOM;
    }
}

# Plex detection
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "HOST" && /plex\.tv/ in value) {
        c$conn$app = APP_PLEX;
    }
    else if (name == "User-Agent" && /PlexMediaServer/ in value) {
        c$conn$app = APP_PLEX;
    }
}

# Spotify detection
event ssl_established(c: connection) {
    if (c$ssl?$server_name && /spotify\.com/ in c$ssl$server_name) {
        c$conn$app = APP_SPOTIFY;
    }
}

# Hulu detection
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "HOST" && /hulu\.com/ in value) {
        c$conn$app = APP_HULU;
    }
}

# Amazon Video detection
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "HOST" && /amazonvideo\.com/ in value) {
        c$conn$app = APP_AMAZON;
    }
    else if (name == "HOST" && /primevideo\.com/ in value) {
        c$conn$app = APP_AMAZON;
    }
}

# Disney+ detection
event ssl_established(c: connection) {
    if (c$ssl?$server_name && /disneyplus\.com/ in c$ssl$server_name) {
        c$conn$app = APP_DISNEY;
    }
}

# VLAN logging
event connection_state_remove(c: connection) {
    if (c?$vlan) {
        c$conn$vlan = c$vlan;
    }
}
