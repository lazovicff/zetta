docker build -t laso-mock -f - . <<EOF && docker run -d -p 4100:4100 --name laso-container laso-mock
FROM rust:1.95-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release && cp target/release/mock-laso /mock-laso

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /mock-laso /mock-laso
CMD ["/mock-laso"]
EOF
