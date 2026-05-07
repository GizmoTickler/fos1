FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/frr-vtysh-sidecar ./cmd/frr-vtysh-sidecar

FROM frrouting/frr:latest
COPY --from=builder /out/frr-vtysh-sidecar /usr/bin/frr-vtysh-sidecar
ENTRYPOINT ["/usr/bin/frr-vtysh-sidecar"]
