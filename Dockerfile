# Digest-pinned (tag alone is mutable); Dependabot keeps digests current.
FROM golang:1.25.11-alpine3.23@sha256:60e626bbde32def8694687d03536ea4341b19e5f068e9a630225a1dfbd0505c9 AS builder

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
