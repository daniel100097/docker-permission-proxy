FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /dsp ./cmd/dsp

FROM alpine:3.21
RUN apk add --no-cache ca-certificates && \
    addgroup -S dpp && adduser -S dpp -G dpp
COPY --from=builder /dsp /usr/local/bin/dsp
USER dpp
ENTRYPOINT ["/usr/local/bin/dsp"]
