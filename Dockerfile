FROM rust:alpine AS build
WORKDIR /app
RUN apk add --no-cache musl-dev
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM alpine:latest
RUN apk add --no-cache ca-certificates curl
COPY --from=build /app/target/release/ipblocklist-api /app
CMD ["/app"]
