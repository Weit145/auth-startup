package storage

import "context"

type Repositories interface {
	CheckHealth(ctx context.Context) error
}
