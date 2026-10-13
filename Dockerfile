FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY templates ./templates
COPY static ./static
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /ucng-certmanager .

FROM alpine:3.24
RUN apk add --no-cache openssl ca-certificates \
    && addgroup -S -g 10001 certmgr \
    && adduser -S -D -H -G certmgr -u 10001 certmgr \
    && mkdir -p /data/certificates \
    && chown -R 10001:10001 /data \
    && chmod 0700 /data /data/certificates
COPY --from=build /ucng-certmanager /usr/local/bin/ucng-certmanager
USER 10001:10001
ENV LISTEN_ADDR=0.0.0.0:8089 DATA_DIR=/data CERT_SOURCE_DIR=/handoff ROOT_CA_DIR=/roots SCRATCH_DIR=/scratch COOKIE_SECURE=true
EXPOSE 8089
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8089/healthz >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/ucng-certmanager"]
