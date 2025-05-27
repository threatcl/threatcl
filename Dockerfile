FROM golang:1.24.3-alpine3.19 AS builder
MAINTAINER Christian Frichot <xntrik@gmail.com>

RUN apk update
RUN apk upgrade
RUN apk add --update git gcc libc-dev libgcc make
WORKDIR /src
COPY . .
ENV CGO_ENABLED=1
RUN go build -o threatcl ./cmd/threatcl

FROM alpine:3.19 AS threatcl
WORKDIR /app
COPY --from=builder /src/threatcl /bin/threatcl
ENTRYPOINT ["/bin/threatcl"]
