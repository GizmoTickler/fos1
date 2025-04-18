FROM golang:1.23 as builder

WORKDIR /workspace
COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o wireguard-controller cmd/wireguard-controller/main.go

FROM alpine:3.19

RUN apk add --no-cache wireguard-tools iproute2 iptables ip6tables

WORKDIR /
COPY --from=builder /workspace/wireguard-controller .

ENTRYPOINT ["/wireguard-controller"]
