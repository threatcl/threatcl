FROM golang:1.19.5-alpine AS builder
MAINTAINER Christian Frichot <xntrik@gmail.com>

RUN apk update
RUN apk upgrade
RUN apk add --update git gcc libc-dev libgcc make
WORKDIR /src
COPY . .
ENV CGO_ENABLED=1
RUN go build -o hcltm ./cmd/hcltm

FROM alpine:3 AS hcltm
WORKDIR /app
COPY --from=builder /src/hcltm /bin/hcltm
ENTRYPOINT ["/bin/hcltm"]
