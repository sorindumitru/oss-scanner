# Scanner image for https://github.com/spiffe/spire.
#
# The audit runs offline, so this build fetches every Go module SPIRE depends on, builds the three shipped binaries
# (spire-server, spire-agent, oidc-discovery-provider) into /src/bin as `make build` does, and compiles every package
# and its tests so reproducers build quickly.

# SPIRE pins its Go version in .go-version. When the image's Go differs from it, `make build` below downloads the pinned
# release into /src/.build, where the Makefile finds it offline, so both `go ...` and `make ...` work during the audit.
# The image has git, make and gcc (cgo is needed for the sqlite3 datastore and the race detector).
FROM golang:1.27-bookworm
ENV DEBIAN_FRONTEND=noninteractive
# curl and openssl for talking to a running server, bundle endpoint or OIDC discovery provider; jq for their output.
# libssl-dev is needed by the TPM simulator (go-tpm-tools) that the tpm_devid node attestor tests compile against.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl jq openssl procps libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# Every module in the build list.
RUN go mod download && go version

# The binaries, as the maintainers build them. A step that fails fails the build, and primary_contact gets the log.
RUN make build \
    && ./bin/spire-server --version && ./bin/spire-agent --version

# Compile every package and every test once (with and without -race) so the build cache is warm.
RUN go build ./... \
    && go test -run '^$' ./... \
    && go test -race -run '^$' ./pkg/... ./support/...

# Baseline unit tests for the security-sensitive areas, so the log shows the image works. A failing test must not
# abort the build.
RUN timeout 1800 go test -timeout 25m \
      ./pkg/common/jwtsvid/... ./pkg/common/x509svid/... ./pkg/common/x509util/... ./pkg/common/peertracker/... \
      ./pkg/server/api/... ./pkg/server/endpoints/... ./pkg/server/authpolicy/... ./pkg/server/authorizedentries/... \
      ./pkg/server/bundle/... ./pkg/server/ca/... ./pkg/agent/endpoints/... ./pkg/agent/api/... \
      ./support/oidc-discovery-provider/... \
    || echo "WARNING: go test reported failures"

# Everything is fetched. From here on the go command must not try to reach a proxy or the checksum database.
ENV GOPROXY=off \
    GOSUMDB=off

CMD ["bash"]
