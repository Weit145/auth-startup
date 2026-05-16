package config

import (
	"os"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	Log  Log  `envPrefix:""`
	GRPC GRPC `envPrefix:""`
	DB   DB   `envPrefix:""`
	JWT  JWT  `envPrefix:""`
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
	}
	return cfg
}
