FROM alpine:3.19

RUN apk add --no-cache wireguard-tools iproute2 iptables ip6tables bash

COPY scripts/wireguard-daemon.sh /usr/local/bin/wireguard-daemon.sh
RUN chmod +x /usr/local/bin/wireguard-daemon.sh

ENTRYPOINT ["/usr/local/bin/wireguard-daemon.sh"]
