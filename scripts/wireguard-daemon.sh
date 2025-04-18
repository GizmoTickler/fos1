#!/bin/bash
set -e

# Load WireGuard kernel module if needed
if ! lsmod | grep -q wireguard; then
    echo "Loading WireGuard kernel module"
    modprobe wireguard
fi

# Watch for configuration changes
echo "Starting WireGuard daemon"
echo "Watching for configuration changes in /etc/wireguard"

# Function to apply configuration
apply_config() {
    local config_file="$1"
    local interface_name=$(basename "$config_file" .conf)
    
    echo "Applying configuration for $interface_name"
    
    # Check if interface exists
    if ip link show "$interface_name" &>/dev/null; then
        echo "Interface $interface_name exists, updating"
        wg syncconf "$interface_name" "$config_file"
    else
        echo "Interface $interface_name does not exist, creating"
        ip link add dev "$interface_name" type wireguard
        wg setconf "$interface_name" "$config_file"
        
        # Extract addresses from config
        grep -E "^Address" "$config_file" | while read -r line; do
            address=$(echo "$line" | awk '{print $3}')
            echo "Adding address $address to $interface_name"
            ip addr add "$address" dev "$interface_name"
        done
        
        # Extract MTU from config
        mtu=$(grep -E "^MTU" "$config_file" | awk '{print $3}')
        if [ -n "$mtu" ]; then
            echo "Setting MTU $mtu on $interface_name"
            ip link set mtu "$mtu" dev "$interface_name"
        fi
        
        # Bring up the interface
        ip link set up dev "$interface_name"
        
        # Run PostUp commands
        grep -E "^PostUp" "$config_file" | while read -r line; do
            command=$(echo "$line" | cut -d'=' -f2- | sed -e 's/^[[:space:]]*//')
            command=$(echo "$command" | sed "s/%i/$interface_name/g")
            echo "Running PostUp command: $command"
            eval "$command"
        done
    fi
}

# Apply initial configurations
for config_file in /etc/wireguard/*.conf; do
    if [ -f "$config_file" ]; then
        apply_config "$config_file"
    fi
done

# Watch for changes
inotifywait -m -e create -e modify -e delete /etc/wireguard --format "%w%f" | while read -r file; do
    if [[ "$file" == *.conf ]]; then
        if [ -f "$file" ]; then
            apply_config "$file"
        else
            # File was deleted
            interface_name=$(basename "$file" .conf)
            if ip link show "$interface_name" &>/dev/null; then
                echo "Configuration for $interface_name was deleted, removing interface"
                
                # Run PreDown commands
                if [ -f "$file.bak" ]; then
                    grep -E "^PreDown" "$file.bak" | while read -r line; do
                        command=$(echo "$line" | cut -d'=' -f2- | sed -e 's/^[[:space:]]*//')
                        command=$(echo "$command" | sed "s/%i/$interface_name/g")
                        echo "Running PreDown command: $command"
                        eval "$command"
                    done
                fi
                
                ip link delete dev "$interface_name"
                
                # Run PostDown commands
                if [ -f "$file.bak" ]; then
                    grep -E "^PostDown" "$file.bak" | while read -r line; do
                        command=$(echo "$line" | cut -d'=' -f2- | sed -e 's/^[[:space:]]*//')
                        command=$(echo "$command" | sed "s/%i/$interface_name/g")
                        echo "Running PostDown command: $command"
                        eval "$command"
                    done
                    rm "$file.bak"
                fi
            fi
        fi
    fi
done
