FROM golang:1.21-alpine as builder

WORKDIR /app

# Copy Go module files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY pkg/ pkg/

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ntp-controller ./pkg/ntp/cmd/main.go

# Use distroless as runtime image
FROM gcr.io/distroless/static:nonroot

WORKDIR /

# Copy executable
COPY --from=builder /app/ntp-controller /ntp-controller

# Use non-root user
USER 65532:65532

ENTRYPOINT ["/ntp-controller"]