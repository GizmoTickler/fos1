FROM golang:1.26 AS builder

WORKDIR /workspace
COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o /usr/bin/event-correlator ./cmd/event-correlator/main.go

FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /usr/bin/event-correlator /usr/bin/event-correlator

ENTRYPOINT ["/usr/bin/event-correlator"]
