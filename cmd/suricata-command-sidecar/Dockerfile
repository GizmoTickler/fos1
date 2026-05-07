FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/suricata-command-sidecar ./cmd/suricata-command-sidecar

FROM alpine:3.20
COPY --from=builder /out/suricata-command-sidecar /usr/bin/suricata-command-sidecar
ENTRYPOINT ["/usr/bin/suricata-command-sidecar"]
