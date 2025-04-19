##! Script for IoT device detection
##! This script adds detection capabilities for IoT devices

@load base/protocols/conn
@load base/protocols/http
@load base/protocols/dns
@load base/protocols/ssl
@load base/protocols/mqtt
@load policy/protocols/conn/vlan-logging
@load ./app-detection

module IoTDetection;

export {
    # Define IoT device types
    const DEV_AMAZON_ECHO = "amazon-echo" &redef;
    const DEV_GOOGLE_HOME = "google-home" &redef;
    const DEV_NEST = "nest" &redef;
    const DEV_RING = "ring" &redef;
    const DEV_PHILIPS_HUE = "philips-hue" &redef;
    const DEV_SONOS = "sonos" &redef;
    const DEV_ROKU = "roku" &redef;
    const DEV_APPLE_TV = "apple-tv" &redef;
    const DEV_CHROMECAST = "chromecast" &redef;
    const DEV_SMART_TV = "smart-tv" &redef;
    const DEV_SAMSUNG_TV = "samsung-tv" &redef;
    const DEV_LG_TV = "lg-tv" &redef;
    const DEV_VIZIO_TV = "vizio-tv" &redef;
    const DEV_SMART_PLUG = "smart-plug" &redef;
    const DEV_SMART_BULB = "smart-bulb" &redef;
    const DEV_SMART_LOCK = "smart-lock" &redef;
    const DEV_SMART_THERMOSTAT = "smart-thermostat" &redef;
    const DEV_SMART_DOORBELL = "smart-doorbell" &redef;
    const DEV_SMART_CAMERA = "smart-camera" &redef;
    const DEV_SMART_SPEAKER = "smart-speaker" &redef;
    
    # Add to the connection record
    redef record Conn::Info += {
        iot_device: string &optional &log;
        iot_vendor: string &optional &log;
    };
    
    # IoT vendors
    const VENDOR_AMAZON = "amazon" &redef;
    const VENDOR_GOOGLE = "google" &redef;
    const VENDOR_APPLE = "apple" &redef;
    const VENDOR_SAMSUNG = "samsung" &redef;
    const VENDOR_LG = "lg" &redef;
    const VENDOR_PHILIPS = "philips" &redef;
    const VENDOR_SONOS = "sonos" &redef;
    const VENDOR_NEST = "nest" &redef;
    const VENDOR_RING = "ring" &redef;
    const VENDOR_ROKU = "roku" &redef;
    const VENDOR_TP_LINK = "tp-link" &redef;
    const VENDOR_BELKIN = "belkin" &redef;
    const VENDOR_WYZE = "wyze" &redef;
    const VENDOR_ARLO = "arlo" &redef;
}

# Helper function to set IoT device info
function set_iot_info(c: connection, device: string, vendor: string) {
    c$conn$iot_device = device;
    c$conn$iot_vendor = vendor;
    c$conn$app_category = AppDetection::CAT_IOT;
}

###################
# Amazon Echo / Alexa
###################

event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "HOST") {
        if (/alexa\.amazon\.com/ in value) {
            set_iot_info(c, DEV_AMAZON_ECHO, VENDOR_AMAZON);
        }
        else if (/avs-alexa/ in value) {
            set_iot_info(c, DEV_AMAZON_ECHO, VENDOR_AMAZON);
        }
    }
    else if (name == "User-Agent" && /AlexaWebPlayer/ in value) {
        set_iot_info(c, DEV_AMAZON_ECHO, VENDOR_AMAZON);
    }
}

event ssl_established(c: connection) {
    if (c$ssl?$server_name) {
        if (/alexa\.amazon\.com/ in c$ssl$server_name) {
            set_iot_info(c, DEV_AMAZON_ECHO, VENDOR_AMAZON);
        }
        else if (/amazon-ats\.com/ in c$ssl$server_name) {
            set_iot_info(c, DEV_AMAZON_ECHO, VENDOR_AMAZON);
        }
    }
}

###################
# Google Home / Nest
###################

event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "HOST") {
        if (/googlehome/ in value) {
            set_iot_info(c, DEV_GOOGLE_HOME, VENDOR_GOOGLE);
        }
        else if (/nest\.com/ in value) {
            set_iot_info(c, DEV_NEST, VENDOR_NEST);
        }
    }
    else if (name == "User-Agent") {
        if (/Google-Home/ in value) {
            set_iot_info(c, DEV_GOOGLE_HOME, VENDOR_GOOGLE);
        }
        else if (/Nest/ in value) {
            set_iot_info(c, DEV_NEST, VENDOR_NEST);
        }
    }
}

event ssl_established(c: connection) {
    if (c$ssl?$server_name) {
        if (/googlehome/ in c$ssl$server_name) {
            set_iot_info(c, DEV_GOOGLE_HOME, VENDOR_GOOGLE);
        }
        else if (/nest\.com/ in c$ssl$server_name) {
            set_iot_info(c, DEV_NEST, VENDOR_NEST);
        }
    }
}

###################
# Smart TVs
###################

event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "User-Agent") {
        if (/SamsungTV/ in value) {
            set_iot_info(c, DEV_SAMSUNG_TV, VENDOR_SAMSUNG);
        }
        else if (/LG NetCast/ in value) {
            set_iot_info(c, DEV_LG_TV, VENDOR_LG);
        }
        else if (/VIZIO/ in value && /SmartCast/ in value) {
            set_iot_info(c, DEV_VIZIO_TV, "vizio");
        }
        else if (/Roku/ in value) {
            set_iot_info(c, DEV_ROKU, VENDOR_ROKU);
        }
        else if (/AppleTV/ in value) {
            set_iot_info(c, DEV_APPLE_TV, VENDOR_APPLE);
        }
        else if (/Chromecast/ in value) {
            set_iot_info(c, DEV_CHROMECAST, VENDOR_GOOGLE);
        }
    }
}

event ssl_established(c: connection) {
    if (c$ssl?$server_name) {
        if (/samsungcloudsolution\.com/ in c$ssl$server_name) {
            set_iot_info(c, DEV_SAMSUNG_TV, VENDOR_SAMSUNG);
        }
        else if (/lgsmartplatform\.com/ in c$ssl$server_name) {
            set_iot_info(c, DEV_LG_TV, VENDOR_LG);
        }
        else if (/vizio\.com/ in c$ssl$server_name) {
            set_iot_info(c, DEV_VIZIO_TV, "vizio");
        }
        else if (/roku\.com/ in c$ssl$server_name) {
            set_iot_info(c, DEV_ROKU, VENDOR_ROKU);
        }
    }
}

###################
# Smart Home Devices
###################

event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "HOST") {
        if (/philips-hue/ in value || /meethue\.com/ in value) {
            set_iot_info(c, DEV_PHILIPS_HUE, VENDOR_PHILIPS);
        }
        else if (/sonos\.com/ in value) {
            set_iot_info(c, DEV_SONOS, VENDOR_SONOS);
        }
        else if (/ring\.com/ in value) {
            set_iot_info(c, DEV_RING, VENDOR_RING);
        }
    }
}

event ssl_established(c: connection) {
    if (c$ssl?$server_name) {
        if (/philips-hue/ in c$ssl$server_name || /meethue\.com/ in c$ssl$server_name) {
            set_iot_info(c, DEV_PHILIPS_HUE, VENDOR_PHILIPS);
        }
        else if (/sonos\.com/ in c$ssl$server_name) {
            set_iot_info(c, DEV_SONOS, VENDOR_SONOS);
        }
        else if (/ring\.com/ in c$ssl$server_name) {
            set_iot_info(c, DEV_SMART_DOORBELL, VENDOR_RING);
        }
        else if (/tplinkcloud\.com/ in c$ssl$server_name) {
            set_iot_info(c, DEV_SMART_PLUG, VENDOR_TP_LINK);
        }
        else if (/wyzecam\.com/ in c$ssl$server_name) {
            set_iot_info(c, DEV_SMART_CAMERA, VENDOR_WYZE);
        }
        else if (/arlo\.com/ in c$ssl$server_name) {
            set_iot_info(c, DEV_SMART_CAMERA, VENDOR_ARLO);
        }
    }
}

###################
# MQTT IoT Devices
###################

event mqtt_connect(c: connection, msg: MQTT::ConnectMsg) {
    # Client IDs often contain device information
    local client_id = msg$client_id;
    
    if (/echo/i in client_id || /alexa/i in client_id) {
        set_iot_info(c, DEV_AMAZON_ECHO, VENDOR_AMAZON);
    }
    else if (/nest/i in client_id) {
        set_iot_info(c, DEV_NEST, VENDOR_NEST);
    }
    else if (/hue/i in client_id || /philips/i in client_id) {
        set_iot_info(c, DEV_PHILIPS_HUE, VENDOR_PHILIPS);
    }
    else if (/sonos/i in client_id) {
        set_iot_info(c, DEV_SONOS, VENDOR_SONOS);
    }
    else if (/smartplug/i in client_id || /smartbulb/i in client_id) {
        if (/tplink/i in client_id) {
            set_iot_info(c, DEV_SMART_PLUG, VENDOR_TP_LINK);
        }
        else if (/wemo/i in client_id) {
            set_iot_info(c, DEV_SMART_PLUG, VENDOR_BELKIN);
        }
        else {
            # Generic smart plug/bulb
            if (/plug/i in client_id) {
                set_iot_info(c, DEV_SMART_PLUG, "unknown");
            }
            else {
                set_iot_info(c, DEV_SMART_BULB, "unknown");
            }
        }
    }
}

event mqtt_subscribe(c: connection, msg_id: count, topics: MQTT::SubscribeMsg) {
    for (i in topics$topics) {
        local topic = topics$topics[i]$topic;
        
        # Topics often reveal device type and purpose
        if (/smartthings/i in topic) {
            set_iot_info(c, DEV_SMART_HOME, "samsung");
        }
        else if (/nest/i in topic) {
            set_iot_info(c, DEV_NEST, VENDOR_NEST);
        }
        else if (/hue/i in topic) {
            set_iot_info(c, DEV_PHILIPS_HUE, VENDOR_PHILIPS);
        }
        else if (/thermostat/i in topic) {
            set_iot_info(c, DEV_SMART_THERMOSTAT, "unknown");
        }
        else if (/camera/i in topic) {
            set_iot_info(c, DEV_SMART_CAMERA, "unknown");
        }
        else if (/doorbell/i in topic) {
            set_iot_info(c, DEV_SMART_DOORBELL, "unknown");
        }
        else if (/lock/i in topic) {
            set_iot_info(c, DEV_SMART_LOCK, "unknown");
        }
    }
}
