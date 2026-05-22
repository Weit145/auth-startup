package config

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Log   Log   `envPrefix:""`
	GRPC  GRPC  `envPrefix:""`
	DB    DB    `envPrefix:""`
	JWT   JWT   `envPrefix:""`
	Time  Time  `envPrefix:""`
	Kafka Kafka `envPrefix:""`
}

type Time struct {
	AccessTokenTTL            time.Duration `env:"ACCESS_TOKEN_EXPIRE_MINUTES" envDefault:"15"`
	RefreshTokenTTL           time.Duration `env:"REFRESH_TOKEN_EXPIRE_DAYS" envDefault:"30"`
	EmailVerificationTokenTTL time.Duration `env:"EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES" envDefault:"15"`
}

type Kafka struct {
	Brokers            []string `env:"KAFKA_BROKERS" envDefault:"kafka:9092"`
	NotificationsTopic string   `env:"KAFKA_NOTIFICATIONS_TOPIC" envDefault:"notifications"`
}

type JWT struct {
	Secret        string `env:"JWT_SECRET" envDefault:"mysecretkey"`
	RefreshSecret string `env:"JWT_REFRESH_SECRET" envDefault:"myrefreshsecretkey"`
}

type Log struct {
	Level string `env:"LOG_LEVEL" envDefault:"INFO"`
}

type DB struct {
	Address string `env:"DATABASE_URL" envDefault:"postgres://postgres:postgres@db:5432/postgres"`
}

type GRPC struct {
	AuthAddr string `env:"GRPC_AUTH_ADDR" envDefault:":50051"`
}

func envOrDefault(def string, envs ...string) string {
	for _, env := range envs {
		value, ok := os.LookupEnv(env)
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		return value
	}
	return strings.TrimSpace(def)
}

func envListOrDefault(def []string, envs ...string) []string {
	value := envOrDefault(strings.Join(def, ","), envs...)
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}

	if len(result) == 0 {
		return def
	}

	return result
}

func envDurationOrDefault(def time.Duration, numericUnit time.Duration, envs ...string) time.Duration {
	for _, env := range envs {
		value, ok := os.LookupEnv(env)
		if !ok {
			continue
		}

		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}

		if result, err := time.ParseDuration(value); err == nil {
			return result
		}

		if result, err := strconv.Atoi(value); err == nil {
			return time.Duration(result) * numericUnit
		}
	}

	return def
}

func InitConfig() Config {
	_ = godotenv.Load()

	cfg := Config{
		Log: Log{
			Level: envOrDefault("INFO", "LOG_LEVEL"),
		},
		DB: DB{
			Address: envOrDefault("postgres://postgres:postgres@db:5432/postgres", "DATABASE_URL"),
		},
		GRPC: GRPC{
			AuthAddr: envOrDefault(":50051", "GRPC_AUTH_ADDR", "AUTH_GRPC_ADDR"),
		},
		JWT: JWT{
			Secret:        envOrDefault("mysecretkey", "JWT_SECRET"),
			RefreshSecret: envOrDefault("myrefreshsecretkey", "JWT_REFRESH_SECRET"),
		},
		Time: Time{
			AccessTokenTTL:            envDurationOrDefault(15*time.Minute, time.Minute, "ACCESS_TOKEN_EXPIRE_MINUTES"),
			RefreshTokenTTL:           envDurationOrDefault(30*24*time.Hour, 24*time.Hour, "REFRESH_TOKEN_EXPIRE_DAYS"),
			EmailVerificationTokenTTL: envDurationOrDefault(15*time.Minute, time.Minute, "EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES"),
		},
		Kafka: Kafka{
			Brokers:            envListOrDefault([]string{"kafka:9092"}, "KAFKA_BROKERS"),
			NotificationsTopic: envOrDefault("notifications", "KAFKA_NOTIFICATIONS_TOPIC"),
		},
	}
	return cfg
}
