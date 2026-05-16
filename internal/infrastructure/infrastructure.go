package infrastructure

import (
	"github.com/Weit145/auth-startup/internal/config"
)

type Infrastructure struct {
	cfg *config.Config
}

type Infrastructures interface {
	Token
}

func NewInfrastructure(cfg *config.Config) *Infrastructure {
	return &Infrastructure{cfg: cfg}
}
