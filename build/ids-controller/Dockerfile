FROM golang:1.23 as builder

WORKDIR /workspace
COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o ids-controller cmd/ids-controller/main.go

FROM alpine:3.19

RUN apk add --no-cache ca-certificates

WORKDIR /
COPY --from=builder /workspace/ids-controller .

ENTRYPOINT ["/ids-controller"]
