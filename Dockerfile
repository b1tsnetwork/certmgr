FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY templates/ ./templates/
COPY static/ ./static/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/certwatch .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata openssl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /app/data /app/acme-catalog /app/acme-status \
    && chown 65532:65532 /app/data /app/acme-catalog
WORKDIR /app
COPY --from=build /out/certwatch /app/certwatch
USER 65532:65532
ENV TZ=Europe/Berlin
EXPOSE 8080
ENTRYPOINT ["/app/certwatch"]
CMD ["-listen", ":8080", "-data", "/app/data/state.json"]
