# Local from-source image build (`make image`). The released image is built
# from Dockerfile.goreleaser instead; both use the same `FROM scratch` runtime
# shape (static binary + CA certs + nonroot passwd/group from an alpine donor).
FROM golang:1.26.4-alpine3.23@sha256:18b460dd17542c2ba43299a633cf6ebfc1115101509531471d7cfce1019af083 AS builder

RUN apk update
RUN apk upgrade
RUN apk add --update git gcc libc-dev libgcc make
WORKDIR /src
COPY . .
ENV CGO_ENABLED=0
RUN go build -o threatcl ./cmd/threatcl

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS donor

RUN addgroup -S threatcl && adduser -S -G threatcl threatcl

FROM scratch AS threatcl

LABEL org.opencontainers.image.authors="Christian Frichot <xntrik@gmail.com>"

COPY --from=donor /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=donor /etc/passwd /etc/passwd
COPY --from=donor /etc/group /etc/group

# scratch has no /tmp or home dir; the remote-imports loader stages downloads
# under os.TempDir(). Owned by the nonroot user so both are writable.
COPY --from=donor --chown=threatcl:threatcl /tmp /tmp
COPY --from=donor --chown=threatcl:threatcl /home/threatcl /home/threatcl

WORKDIR /app
COPY --from=builder /src/threatcl /bin/threatcl

USER threatcl
ENTRYPOINT ["/bin/threatcl"]
