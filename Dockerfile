FROM golang:1.25-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download
RUN CGO_ENABLED=0 go install github.com/michurin/human-readable-json-logging/cmd/pplog@v0.0.0-20251207065006-861035fdcf92

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/auth-startup ./cmd

FROM alpine:3.22

WORKDIR /app

RUN apk add --no-cache ca-certificates \
	&& addgroup -S app \
	&& adduser -S -G app app

COPY --from=builder /out/auth-startup /app/auth-startup
COPY --from=builder /go/bin/pplog /usr/local/bin/pplog
COPY pplog.env ./pplog.env

ENV LOG_LEVEL=INFO

USER app

EXPOSE 50051

ENTRYPOINT ["pplog", "/app/auth-startup"]
