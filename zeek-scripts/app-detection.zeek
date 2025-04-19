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
    # Define streaming service application types
    const APP_NETFLIX = "netflix" &redef;
    const APP_YOUTUBE = "youtube" &redef;
    const APP_PLEX = "plex" &redef;
    const APP_SPOTIFY = "spotify" &redef;
    const APP_HULU = "hulu" &redef;
    const APP_AMAZON = "amazon-video" &redef;
    const APP_DISNEY = "disney-plus" &redef;
    const APP_HBO = "hbo-max" &redef;
    const APP_TWITCH = "twitch" &redef;
    const APP_APPLE_TV = "apple-tv" &redef;
    const APP_PEACOCK = "peacock" &redef;
    const APP_PARAMOUNT = "paramount-plus" &redef;
    const APP_TUBI = "tubi" &redef;
    const APP_CRUNCHYROLL = "crunchyroll" &redef;

    # Define video conferencing application types
    const APP_ZOOM = "zoom" &redef;
    const APP_TEAMS = "ms-teams" &redef;
    const APP_MEET = "google-meet" &redef;
    const APP_WEBEX = "webex" &redef;
    const APP_SLACK = "slack" &redef;
    const APP_DISCORD = "discord" &redef;

    # Define social media application types
    const APP_FACEBOOK = "facebook" &redef;
    const APP_INSTAGRAM = "instagram" &redef;
    const APP_TWITTER = "twitter" &redef;
    const APP_TIKTOK = "tiktok" &redef;
    const APP_SNAPCHAT = "snapchat" &redef;
    const APP_PINTEREST = "pinterest" &redef;
    const APP_REDDIT = "reddit" &redef;

    # Define gaming platform application types
    const APP_STEAM = "steam" &redef;
    const APP_EPIC = "epic-games" &redef;
    const APP_XBOX = "xbox-live" &redef;
    const APP_PSN = "playstation-network" &redef;
    const APP_NINTENDO = "nintendo" &redef;
    const APP_ROBLOX = "roblox" &redef;
    const APP_MINECRAFT = "minecraft" &redef;

    # Add to the connection record
    redef record Conn::Info += {
        app: string &optional &log;
        vlan: int &optional &log;
        app_category: string &optional &log;
    };

    # Application categories
    const CAT_STREAMING = "streaming" &redef;
    const CAT_GAMING = "gaming" &redef;
    const CAT_SOCIAL = "social-media" &redef;
    const CAT_CONFERENCING = "video-conferencing" &redef;
    const CAT_IOT = "iot" &redef;
    const CAT_PRODUCTIVITY = "productivity" &redef;
}

# Helper function to set application and category
function set_app_info(c: connection, app: string, category: string) {
    c$conn$app = app;
    c$conn$app_category = category;
}

###################
# Streaming Services
###################

# Netflix detection
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "HOST") {
        if (/netflix\.com/ in value) {
            set_app_info(c, APP_NETFLIX, CAT_STREAMING);
        }
        else if (/nflxvideo\.net/ in value) {
            set_app_info(c, APP_NETFLIX, CAT_STREAMING);
        }
        else if (/nflximg\.net/ in value) {
            set_app_info(c, APP_NETFLIX, CAT_STREAMING);
        }
    }
    else if (name == "User-Agent" && /Netflix/ in value) {
        set_app_info(c, APP_NETFLIX, CAT_STREAMING);
    }
}

# YouTube detection
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "HOST") {
        if (/youtube\.com/ in value) {
            set_app_info(c, APP_YOUTUBE, CAT_STREAMING);
        }
        else if (/youtu\.be/ in value) {
            set_app_info(c, APP_YOUTUBE, CAT_STREAMING);
        }
        else if (/ytimg\.com/ in value) {
            set_app_info(c, APP_YOUTUBE, CAT_STREAMING);
        }
        else if (/googlevideo\.com/ in value) {
            set_app_info(c, APP_YOUTUBE, CAT_STREAMING);
        }
    }
    else if (name == "User-Agent" && /YouTube/ in value) {
        set_app_info(c, APP_YOUTUBE, CAT_STREAMING);
    }
}

# Plex detection
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "HOST") {
        if (/plex\.tv/ in value) {
            set_app_info(c, APP_PLEX, CAT_STREAMING);
        }
        else if (/plex\.direct/ in value) {
            set_app_info(c, APP_PLEX, CAT_STREAMING);
        }
    }
    else if (name == "User-Agent" && /PlexMediaServer/ in value) {
        set_app_info(c, APP_PLEX, CAT_STREAMING);
    }
}

event ssl_established(c: connection) {
    if (c$ssl?$server_name) {
        if (/plex\.tv/ in c$ssl$server_name) {
            set_app_info(c, APP_PLEX, CAT_STREAMING);
        }
        else if (/plex\.direct/ in c$ssl$server_name) {
            set_app_info(c, APP_PLEX, CAT_STREAMING);
        }
    }
}

# Spotify detection
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "HOST") {
        if (/spotify\.com/ in value) {
            set_app_info(c, APP_SPOTIFY, CAT_STREAMING);
        }
        else if (/scdn\.co/ in value) {
            set_app_info(c, APP_SPOTIFY, CAT_STREAMING);
        }
    }
}

event ssl_established(c: connection) {
    if (c$ssl?$server_name) {
        if (/spotify\.com/ in c$ssl$server_name) {
            set_app_info(c, APP_SPOTIFY, CAT_STREAMING);
        }
        else if (/scdn\.co/ in c$ssl$server_name) {
            set_app_info(c, APP_SPOTIFY, CAT_STREAMING);
        }
    }
}

# Disney+ detection
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "HOST") {
        if (/disneyplus\.com/ in value) {
            set_app_info(c, APP_DISNEY, CAT_STREAMING);
        }
        else if (/disney-plus\.net/ in value) {
            set_app_info(c, APP_DISNEY, CAT_STREAMING);
        }
        else if (/dssott\.com/ in value) {
            set_app_info(c, APP_DISNEY, CAT_STREAMING);
        }
    }
}

event ssl_established(c: connection) {
    if (c$ssl?$server_name) {
        if (/disneyplus\.com/ in c$ssl$server_name) {
            set_app_info(c, APP_DISNEY, CAT_STREAMING);
        }
        else if (/dssott\.com/ in c$ssl$server_name) {
            set_app_info(c, APP_DISNEY, CAT_STREAMING);
        }
    }
}

# Hulu detection
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "HOST") {
        if (/hulu\.com/ in value) {
            set_app_info(c, APP_HULU, CAT_STREAMING);
        }
        else if (/hulustream\.com/ in value) {
            set_app_info(c, APP_HULU, CAT_STREAMING);
        }
    }
}

event ssl_established(c: connection) {
    if (c$ssl?$server_name) {
        if (/hulu\.com/ in c$ssl$server_name) {
            set_app_info(c, APP_HULU, CAT_STREAMING);
        }
    }
}

# Amazon Prime Video detection
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "HOST") {
        if (/amazonvideo\.com/ in value) {
            set_app_info(c, APP_AMAZON, CAT_STREAMING);
        }
        else if (/primevideo\.com/ in value) {
            set_app_info(c, APP_AMAZON, CAT_STREAMING);
        }
        else if (/amazon\.com\/Prime-Video/ in value) {
            set_app_info(c, APP_AMAZON, CAT_STREAMING);
        }
        else if (/aiv-cdn\.net/ in value) {
            set_app_info(c, APP_AMAZON, CAT_STREAMING);
        }
        else if (/aiv-delivery\.net/ in value) {
            set_app_info(c, APP_AMAZON, CAT_STREAMING);
        }
    }
}

# HBO Max detection
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "HOST") {
        if (/hbomax\.com/ in value) {
            set_app_info(c, APP_HBO, CAT_STREAMING);
        }
        else if (/hbo\.com/ in value) {
            set_app_info(c, APP_HBO, CAT_STREAMING);
        }
    }
}

event ssl_established(c: connection) {
    if (c$ssl?$server_name) {
        if (/hbomax\.com/ in c$ssl$server_name) {
            set_app_info(c, APP_HBO, CAT_STREAMING);
        }
    }
}

# Twitch detection
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "HOST") {
        if (/twitch\.tv/ in value) {
            set_app_info(c, APP_TWITCH, CAT_STREAMING);
        }
        else if (/ttvnw\.net/ in value) {
            set_app_info(c, APP_TWITCH, CAT_STREAMING);
        }
        else if (/jtvnw\.net/ in value) {
            set_app_info(c, APP_TWITCH, CAT_STREAMING);
        }
    }
}

###################
# Video Conferencing
###################

# Zoom detection
event ssl_established(c: connection) {
    if (c$ssl?$server_name) {
        if (/zoom\.us/ in c$ssl$server_name) {
            set_app_info(c, APP_ZOOM, CAT_CONFERENCING);
        }
        else if (/zoomgov\.com/ in c$ssl$server_name) {
            set_app_info(c, APP_ZOOM, CAT_CONFERENCING);
        }
    }
}

# Microsoft Teams detection
event ssl_established(c: connection) {
    if (c$ssl?$server_name) {
        if (/teams\.microsoft\.com/ in c$ssl$server_name) {
            set_app_info(c, APP_TEAMS, CAT_CONFERENCING);
        }
        else if (/teams\.live\.com/ in c$ssl$server_name) {
            set_app_info(c, APP_TEAMS, CAT_CONFERENCING);
        }
    }
}

# Google Meet detection
event ssl_established(c: connection) {
    if (c$ssl?$server_name) {
        if (/meet\.google\.com/ in c$ssl$server_name) {
            set_app_info(c, APP_MEET, CAT_CONFERENCING);
        }
    }
}

# Webex detection
event ssl_established(c: connection) {
    if (c$ssl?$server_name) {
        if (/webex\.com/ in c$ssl$server_name) {
            set_app_info(c, APP_WEBEX, CAT_CONFERENCING);
        }
    }
}

###################
# Social Media
###################

# Facebook detection
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "HOST") {
        if (/facebook\.com/ in value) {
            set_app_info(c, APP_FACEBOOK, CAT_SOCIAL);
        }
        else if (/fbcdn\.net/ in value) {
            set_app_info(c, APP_FACEBOOK, CAT_SOCIAL);
        }
    }
}

event ssl_established(c: connection) {
    if (c$ssl?$server_name) {
        if (/facebook\.com/ in c$ssl$server_name) {
            set_app_info(c, APP_FACEBOOK, CAT_SOCIAL);
        }
        else if (/fbcdn\.net/ in c$ssl$server_name) {
            set_app_info(c, APP_FACEBOOK, CAT_SOCIAL);
        }
    }
}

# Instagram detection
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "HOST") {
        if (/instagram\.com/ in value) {
            set_app_info(c, APP_INSTAGRAM, CAT_SOCIAL);
        }
        else if (/cdninstagram\.com/ in value) {
            set_app_info(c, APP_INSTAGRAM, CAT_SOCIAL);
        }
    }
}

event ssl_established(c: connection) {
    if (c$ssl?$server_name) {
        if (/instagram\.com/ in c$ssl$server_name) {
            set_app_info(c, APP_INSTAGRAM, CAT_SOCIAL);
        }
    }
}

# Twitter detection
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "HOST") {
        if (/twitter\.com/ in value) {
            set_app_info(c, APP_TWITTER, CAT_SOCIAL);
        }
        else if (/twimg\.com/ in value) {
            set_app_info(c, APP_TWITTER, CAT_SOCIAL);
        }
    }
}

event ssl_established(c: connection) {
    if (c$ssl?$server_name) {
        if (/twitter\.com/ in c$ssl$server_name) {
            set_app_info(c, APP_TWITTER, CAT_SOCIAL);
        }
    }
}

# TikTok detection
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "HOST") {
        if (/tiktok\.com/ in value) {
            set_app_info(c, APP_TIKTOK, CAT_SOCIAL);
        }
        else if (/tiktokcdn\.com/ in value) {
            set_app_info(c, APP_TIKTOK, CAT_SOCIAL);
        }
        else if (/musical\.ly/ in value) {
            set_app_info(c, APP_TIKTOK, CAT_SOCIAL);
        }
    }
}

###################
# Gaming Platforms
###################

# Steam detection
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "HOST") {
        if (/steampowered\.com/ in value) {
            set_app_info(c, APP_STEAM, CAT_GAMING);
        }
        else if (/steamcommunity\.com/ in value) {
            set_app_info(c, APP_STEAM, CAT_GAMING);
        }
        else if (/steamusercontent\.com/ in value) {
            set_app_info(c, APP_STEAM, CAT_GAMING);
        }
        else if (/steamstatic\.com/ in value) {
            set_app_info(c, APP_STEAM, CAT_GAMING);
        }
    }
    else if (name == "User-Agent" && /Valve Steam/ in value) {
        set_app_info(c, APP_STEAM, CAT_GAMING);
    }
}

# Epic Games detection
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "HOST") {
        if (/epicgames\.com/ in value) {
            set_app_info(c, APP_EPIC, CAT_GAMING);
        }
        else if (/unrealengine\.com/ in value) {
            set_app_info(c, APP_EPIC, CAT_GAMING);
        }
    }
}

# Xbox Live detection
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "HOST") {
        if (/xbox\.com/ in value) {
            set_app_info(c, APP_XBOX, CAT_GAMING);
        }
        else if (/xboxlive\.com/ in value) {
            set_app_info(c, APP_XBOX, CAT_GAMING);
        }
    }
}

# PlayStation Network detection
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "HOST") {
        if (/playstation\.com/ in value) {
            set_app_info(c, APP_PSN, CAT_GAMING);
        }
        else if (/playstation\.net/ in value) {
            set_app_info(c, APP_PSN, CAT_GAMING);
        }
        else if (/sonyentertainmentnetwork\.com/ in value) {
            set_app_info(c, APP_PSN, CAT_GAMING);
        }
    }
}

# Minecraft detection
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "HOST") {
        if (/minecraft\.net/ in value) {
            set_app_info(c, APP_MINECRAFT, CAT_GAMING);
        }
        else if (/mojang\.com/ in value) {
            set_app_info(c, APP_MINECRAFT, CAT_GAMING);
        }
    }
}

# VLAN logging
event connection_state_remove(c: connection) {
    if (c?$vlan) {
        c$conn$vlan = c$vlan;
    }
}
