FROM --platform=$BUILDPLATFORM golang:1.20-alpine AS builder

ARG BUILDPLATFORM
ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application for the target platform
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -a -installsuffix cgo -o dpi-framework ./cmd/dpi-framework

# Use a minimal alpine image for the final container
FROM --platform=$TARGETPLATFORM alpine:3.17

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/dpi-framework /app/dpi-framework

# Create directory for configuration
RUN mkdir -p /etc/dpi-framework

# Set the entrypoint
ENTRYPOINT ["/app/dpi-framework"]
