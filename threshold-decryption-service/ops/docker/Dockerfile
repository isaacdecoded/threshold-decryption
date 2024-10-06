FROM rust:1.79.0 AS builder

RUN USER=root cargo new --bin app
WORKDIR /app

COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml

# Cache dependencies
RUN cargo build --release
RUN rm src/*.rs

COPY ./src ./src

# Build application
RUN rm -f ./target/release/deps/threshold_decryption_service*
RUN cargo build --release

FROM debian:sid-slim
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/threshold_decryption_service /usr/src/app/threshold_decryption_service
EXPOSE 3000
CMD ["./usr/src/app/threshold_decryption_service"]
