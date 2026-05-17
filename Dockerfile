FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /dsp ./cmd/dsp

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /dsp /usr/local/bin/dsp
ENTRYPOINT ["/usr/local/bin/dsp"]
