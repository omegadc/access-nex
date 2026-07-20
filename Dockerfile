# syntax=docker/dockerfile:1

# ── Build stage ────────────────────────────────────────────────────────────────
# CGO_ENABLED=0 works because every dependency here is pure Go: modernc.org/sqlite
# is a CGO-free SQLite implementation and pgx's stdlib driver needs no C library
# either, so the binary is fully static — no libc, no glibc/musl split to worry
# about between the build and final images.
FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/access-nex .
# distroless/static has no shell to `mkdir` in, and its default nonroot user
# (UID 65532) can't write into a VOLUME directory Docker creates as root —
# so the writable data directory is created here, with the right owner,
# and copied over instead.
RUN mkdir -p /out/data && chown 65532:65532 /out/data

# ── Final stage ────────────────────────────────────────────────────────────────
# distroless/static: no shell, no package manager, just the binary, CA certs
# (needed for outbound HTTPS to external providers/SMTP), and tzdata. Runs as
# the built-in nonroot user. Because there's no shell here, initialization
# can't be a wrapper script — `access-nex server` auto-initializes the local
# provider on first run instead (see internal/cli/cli.go), so ENTRYPOINT can
# point straight at the binary.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/access-nex /usr/local/bin/access-nex
COPY --from=build --chown=65532:65532 /out/data /data

# --config holds the AES box key and the signing key, and — unless --db
# points at PostgreSQL — the SQLite database itself. Mount a volume here in
# production so keys and data survive container recreation.
VOLUME ["/data"]
EXPOSE 8080

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/access-nex"]
CMD ["server", "--config", "/data", "--addr", ":8080"]
