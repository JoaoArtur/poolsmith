# syntax=docker/dockerfile:1.7

# ---- builder ----------------------------------------------------------------
FROM golang:1.22-alpine AS builder
WORKDIR /src

# Leverage the mod cache: copy only the manifest first so `go mod download`
# can be cached across rebuilds when sources change.
COPY go.mod ./
RUN go mod download

COPY . .

# Build a fully static, stripped, CGO-free binary. The -trimpath + -w -s flags
# shrink the output ~25% by removing DWARF symbols and absolute paths.
ARG VERSION=dev
ENV CGO_ENABLED=0 GOOS=linux
RUN go build \
      -trimpath \
      -ldflags "-w -s -X main.version=${VERSION}" \
      -o /out/poolsmith \
      ./cmd/poolsmith

# ---- runtime ---------------------------------------------------------------
# Using `scratch` — no shell, no libc, no package manager. Final image ~8 MB.
FROM scratch
COPY --from=builder /out/poolsmith /poolsmith

# The default config path. Mount your real config over this via ConfigMap.
VOLUME ["/etc/poolsmith"]

EXPOSE 6432

ENTRYPOINT ["/poolsmith"]
CMD ["-config", "/etc/poolsmith/poolsmith.ini"]
