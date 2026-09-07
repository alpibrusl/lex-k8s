# The wall, as a container.
#
# Two stages: a builder with the toolchain and git (the lex-os
# dependencies are git revs, not registry crates), and a runtime that
# carries the binary and nothing else.
#
# The image is built with `--features serve`. Without it the binary has
# no server and says so — see `cmd_serve` in src/main.rs. That is the
# same "refuse, don't downgrade" rule the rest of this repo follows, and
# it is why the feature is named in exactly one place: here.
FROM rust:1-bookworm AS build
WORKDIR /src

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Dependencies first, so a change to src/ does not refetch the world.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs \
 && echo '' > src/lib.rs \
 && cargo build --release --features serve --locked 2>/dev/null || true

COPY src ./src
COPY tests ./tests
# `touch` because the stub above may have left a newer mtime than the
# real sources, and cargo would then skip the rebuild that matters.
RUN touch src/main.rs src/lib.rs \
 && cargo build --release --features serve --locked

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 65532 --user-group --home-dir /nonexistent --shell /usr/sbin/nologin wall
COPY --from=build /src/target/release/lex-k8s /usr/local/bin/lex-k8s
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/lex-k8s"]
CMD ["serve", "--cert", "/tls/tls.crt", "--key", "/tls/tls.key"]
