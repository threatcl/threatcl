# Local from-source image build (`make image`). The released image is built
# from Dockerfile.goreleaser instead; both use the same `FROM scratch` runtime
# shape (static binary + CA certs + nonroot passwd/group from an alpine donor).
FROM golang:1.27.4-alpine3.23@sha256:f70850ef6ce341e8b6427f677049145d63c0b7ce002d4d7e3d464828b1b96dcd AS builder

RUN apk update
RUN apk upgrade
RUN apk add --update git gcc libc-dev libgcc make
WORKDIR /src
COPY . .
ENV CGO_ENABLED=0
RUN go build -o threatcl ./cmd/threatcl

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS donor

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
