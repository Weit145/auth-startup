FROM golang:1.25-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/auth-startup ./cmd

FROM alpine:3.22

WORKDIR /app

RUN apk add --no-cache ca-certificates \
	&& addgroup -S app \
	&& adduser -S -G app app

COPY --from=builder /out/auth-startup /app/auth-startup

ENV LOG_LEVEL=INFO

USER app

EXPOSE 50051

ENTRYPOINT ["/app/auth-startup"]
