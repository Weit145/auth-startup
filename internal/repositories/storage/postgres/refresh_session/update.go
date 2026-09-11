package refreshsession

import (
	"context"
	"fmt"

	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func RevokeSession(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
	token string,
) error {
	revokeSessionStmt := `
		UPDATE refresh_sessions
		SET revoked_at = now()
		WHERE user_id = $1
			AND refresh_token_hash = $2
			AND revoked_at IS NULL
	`
	if _, err := tx.Exec(ctx, revokeSessionStmt, userID, token); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("revoke refresh session: %w", err))
	}
	return nil
}
