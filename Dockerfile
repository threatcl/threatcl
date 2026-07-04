# Digest-pinned (tag alone is mutable); Dependabot keeps digests current.
FROM golang:1.25.9-alpine3.23@sha256:5caaf1cca9dc351e13deafbc3879fd4754801acba8653fa9540cea125d01a71f AS builder

RUN apk update
RUN apk upgrade
RUN apk add --update git gcc libc-dev libgcc make
WORKDIR /src
COPY . .
ENV CGO_ENABLED=0
RUN go build -o threatcl ./cmd/threatcl

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS threatcl

MAINTAINER Christian Frichot <xntrik@gmail.com>
LABEL org.opencontainers.image.authors="Christian Frichot <xntrik@gmail.com>"

RUN addgroup -S threatcl && adduser -S -G threatcl threatcl

WORKDIR /app
COPY --from=builder /src/threatcl /bin/threatcl

USER threatcl
ENTRYPOINT ["/bin/threatcl"]
