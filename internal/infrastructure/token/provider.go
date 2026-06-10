package token

import (
	"crypto/rsa"
	"time"
)

type Settings struct {
	PrivateKey     *rsa.PrivateKey
	RefreshSecret  string
	AccessTokenTTL time.Duration
}

type Provider struct {
	cfg Settings
}

func NewProvider(cfg Settings) *Provider {
	return &Provider{cfg: cfg}
}
