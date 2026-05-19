FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /dsp ./cmd/dsp

FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates zenity && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --system dpp && useradd --system --gid dpp --home-dir /nonexistent --no-create-home dpp
COPY --from=builder /dsp /usr/local/bin/dsp
USER dpp
ENTRYPOINT ["/usr/local/bin/dsp"]
