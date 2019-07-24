# Build the manager binary
FROM golang:1.10.3 as builder

# Copy in the go src
WORKDIR /go/src/github.com/appscode/guard
COPY main.go main.go
COPY auth/ auth/
COPY commands/ commands/
COPY installer/ installer/
COPY server/ server/
COPY util/ util/
COPY vendor/ vendor/

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o guard main.go

# Copy the controller-guard into a thin image
FROM ubuntu:latest
WORKDIR /
COPY --from=builder /go/src/github.com/appscode/guard .
ENTRYPOINT ["/guard"]
