FROM rust:latest AS builder
WORKDIR /usr/src/app
COPY . .
RUN cargo build --release

FROM alpine:latest
WORKDIR /usr/local/bin
COPY --from=builder /usr/src/app/target/release/ .
CMD ["ls"]