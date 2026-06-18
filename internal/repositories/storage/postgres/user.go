package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Weit145/auth-startup/internal/domain"
	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

func (r *Repository) CreateUserWithEmailVerificationToken(ctx context.Context, account domain.Account, token domain.EmailVerificationTokenHash) (domain.User, error) {
	tokenExpiresAt, ok := token.ExpiresAt()
	if !ok {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("email verification token expiration is not set"))
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("begin create user tx: %w", err))
	}
	defer tx.Rollback(ctx)

	result, err := UpsertUnverifiedUser(ctx, tx, account)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, err)
	}

	if err := InvalidateEmailVerificationTokens(ctx, tx, result.ID()); err != nil {
		return domain.User{}, logger.WrapError(ctx, err)
	}

	if err := AddEmailVerificationToken(ctx, tx, result.ID(), token.Value(), tokenExpiresAt); err != nil {
		return domain.User{}, logger.WrapError(ctx, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("commit create user tx: %w", err))
	}

	return result, nil
}

func (r *Repository) UpdateTokenEmail(ctx context.Context, email string, tokenHash domain.EmailVerificationTokenHash) (domain.User, error) {
	tokenExpiresAt, ok := tokenHash.ExpiresAt()
	if !ok {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("email verification token expiration is not set"))
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("begin update email verification token tx: %w", err))
	}
	defer tx.Rollback(ctx)

	user, err := GetUnverifiedUserByEmail(ctx, tx, email)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, err)
	}

	if err := InvalidateEmailVerificationTokens(ctx, tx, user.ID()); err != nil {
		return domain.User{}, logger.WrapError(ctx, err)
	}

	if err := AddEmailVerificationToken(ctx, tx, user.ID(), tokenHash.Value(), tokenExpiresAt); err != nil {
		return domain.User{}, logger.WrapError(ctx, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("commit update email verification token tx: %w", err))
	}

	return *user, nil
}

func UpsertUnverifiedUser(ctx context.Context, tx pgx.Tx, account domain.Account) (domain.User, error) {
	createUserStmt := `
		INSERT INTO users (id, email, password_hash, name, role)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (email) DO UPDATE
		SET
			password_hash = EXCLUDED.password_hash,
			name = EXCLUDED.name
		WHERE users.email_verified_at IS NULL
		RETURNING id, email, name, role`

	var (
		id    uuid.UUID
		name  string
		email string
		role  string
	)

	user := account.User()
	err := tx.QueryRow(ctx, createUserStmt, user.ID(), user.Email(), account.PasswordHash(), user.Name(), user.Role()).
		Scan(&id, &email, &name, &role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, logger.WrapError(ctx, fmt.Errorf("upsert user: %w", errs.ErrAlreadyExists))
		}
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("upsert user: %w", err))
	}

	result, err := domain.NewUser(id, email, name, role)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("build user from database row: %w", err))
	}

	return *result, nil
}

func (r *Repository) GetUserByEmail(ctx context.Context, email string) (*domain.Account, error) {
	query := `
		SELECT id, email, password_hash, name, role, email_verified_at
		FROM users
		WHERE email = $1 AND email_verified_at IS NOT NULL
	`
	var (
		id              uuid.UUID
		emailDB         string
		passwordHash    string
		name            string
		role            string
		emailVerifiedAt time.Time
	)

	err := r.db.QueryRow(ctx, query, email).Scan(&id, &emailDB, &passwordHash, &name, &role, &emailVerifiedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, logger.WrapError(ctx, errs.ErrNotFound)
		}
		return nil, logger.WrapError(ctx, fmt.Errorf("query user by email: %w", err))
	}

	result, err := domain.CreateUserAccount(id, emailDB, passwordHash, name, role, &emailVerifiedAt)
	if err != nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("build user from database row: %w", err))
	}

	return result, nil
}

func VerifyUserEmail(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	verifyUserStmt := `
		UPDATE users
		SET email_verified_at = now()
		WHERE id = $1 AND email_verified_at IS NULL
	`

	result, err := tx.Exec(ctx, verifyUserStmt, userID)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("verify user email: %w", err))
	}
	if result.RowsAffected() == 0 {
		return logger.WrapError(ctx, errs.ErrNotFound)
	}

	return nil
}

func GetUserByID(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (*domain.User, error) {
	query := `
			SELECT id, email, name, role
			FROM users
			WHERE id = $1 AND email_verified_at IS NOT NULL
		`
	var (
		id      uuid.UUID
		emailDB string
		name    string
		role    string
	)

	err := tx.QueryRow(ctx, query, userID).Scan(&id, &emailDB, &name, &role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, logger.WrapError(ctx, errs.ErrNotFound)
		}
		return nil, logger.WrapError(ctx, fmt.Errorf("query user by id: %w", err))
	}

	result, err := domain.NewUser(id, emailDB, name, role)
	if err != nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("build user from database row: %w", err))
	}

	return result, nil
}

func GetUnverifiedUserByEmail(ctx context.Context, tx pgx.Tx, email string) (*domain.User, error) {
	query := `
		SELECT id, email, name, role
		FROM users
		WHERE email = $1 AND email_verified_at IS NULL
		FOR UPDATE
	`
	var (
		id      uuid.UUID
		emailDB string
		name    string
		role    string
	)

	err := tx.QueryRow(ctx, query, email).Scan(&id, &emailDB, &name, &role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, logger.WrapError(ctx, errs.ErrNotFound)
		}
		return nil, logger.WrapError(ctx, fmt.Errorf("query unverified user by email: %w", err))
	}

	result, err := domain.NewUser(id, emailDB, name, role)
	if err != nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("build user from database row: %w", err))
	}

	return result, nil
}

func GetVerifiedUserByEmail(ctx context.Context, tx pgx.Tx, email string) (*domain.User, error) {
	query := `
		SELECT id, email, name, role
		FROM users
		WHERE email = $1 AND email_verified_at IS NOT NULL
		FOR UPDATE
	`
	var (
		id      uuid.UUID
		emailDB string
		name    string
		role    string
	)

	err := tx.QueryRow(ctx, query, email).Scan(&id, &emailDB, &name, &role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, logger.WrapError(ctx, errs.ErrNotFound)
		}
		return nil, logger.WrapError(ctx, fmt.Errorf("query verified user by email: %w", err))
	}

	result, err := domain.NewUser(id, emailDB, name, role)
	if err != nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("build user from database row: %w", err))
	}

	return result, nil
}

func UpdateUserPassword(ctx context.Context, tx pgx.Tx, userID uuid.UUID, passwordHash string) (*domain.User, error) {
	query := `
		UPDATE users
		SET password_hash = $2
		WHERE id = $1 AND email_verified_at IS NOT NULL
		RETURNING id, email, name, role
	`
	var (
		id    uuid.UUID
		email string
		name  string
		role  string
	)

	err := tx.QueryRow(ctx, query, userID, passwordHash).Scan(&id, &email, &name, &role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, logger.WrapError(ctx, errs.ErrNotFound)
		}
		return nil, logger.WrapError(ctx, fmt.Errorf("update user password: %w", err))
	}

	result, err := domain.NewUser(id, email, name, role)
	if err != nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("build user from database row: %w", err))
	}

	return result, nil
}

func GetVerifiedUserWithActiveSession(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (*domain.User, string, error) {
	query := `
		SELECT u.id, u.email, u.name, u.role, u.password_hash
		FROM users AS u
		WHERE u.id = $1
			AND u.email_verified_at IS NOT NULL
			AND EXISTS (
				SELECT 1
				FROM refresh_sessions AS rs
				WHERE rs.user_id = u.id
					AND rs.revoked_at IS NULL
					AND rs.expires_at > now()
			)
		FOR UPDATE
	`
	var (
		id           uuid.UUID
		email        string
		name         string
		role         string
		passwordHash string
	)

	err := tx.QueryRow(ctx, query, userID).Scan(&id, &email, &name, &role, &passwordHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", logger.WrapError(ctx, errs.ErrUnauthorized)
		}
		return nil, "", logger.WrapError(ctx, fmt.Errorf("query user with active session: %w", err))
	}

	result, err := domain.NewUser(id, email, name, role)
	if err != nil {
		return nil, "", logger.WrapError(ctx, fmt.Errorf("build user from database row: %w", err))
	}

	return result, passwordHash, nil
}

func RevokeActiveUserSessions(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	query := `
		UPDATE refresh_sessions
		SET revoked_at = now()
		WHERE user_id = $1
			AND revoked_at IS NULL
			AND expires_at > now()
	`

	if _, err := tx.Exec(ctx, query, userID); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("revoke active user sessions: %w", err))
	}

	return nil
}

func (r *Repository) PasswordRequest(ctx context.Context, email string, tokenHash domain.EmailVerificationTokenHash) (domain.User, error) {
	tokenExpiresAt, ok := tokenHash.ExpiresAt()
	if !ok {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("password reset token expiration is not set"))
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("begin password request tx: %w", err))
	}
	defer tx.Rollback(ctx)

	user, err := GetVerifiedUserByEmail(ctx, tx, email)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, err)
	}

	if err := InvalidatePasswordResetTokens(ctx, tx, user.ID()); err != nil {
		return domain.User{}, logger.WrapError(ctx, err)
	}

	if err := AddPasswordResetToken(ctx, tx, user.ID(), tokenHash.Value(), tokenExpiresAt); err != nil {
		return domain.User{}, logger.WrapError(ctx, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("commit password request tx: %w", err))
	}

	return *user, nil
}

func (r *Repository) PasswordConfirm(ctx context.Context, userID uuid.UUID, tokenHash domain.EmailVerificationTokenHash, passwordHash string) (domain.User, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("begin password confirm tx: %w", err))
	}
	defer tx.Rollback(ctx)

	verifiedUserID, err := VerifyPasswordResetToken(ctx, tx, userID, tokenHash.Value())
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("use password reset token: %w", err))
	}

	user, err := UpdateUserPassword(ctx, tx, verifiedUserID, passwordHash)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("commit password confirm tx: %w", err))
	}

	return *user, nil
}

func (r *Repository) ChangePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPasswordHash string) (domain.User, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("begin change password tx: %w", err))
	}
	defer tx.Rollback(ctx)

	user, currentPasswordHash, err := GetVerifiedUserWithActiveSession(ctx, tx, userID)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(currentPasswordHash), []byte(oldPassword)); err != nil {
		return domain.User{}, logger.WrapError(ctx, errs.ErrUnauthorized)
	}

	updatedUser, err := UpdateUserPassword(ctx, tx, user.ID(), newPasswordHash)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, err)
	}

	if err := RevokeActiveUserSessions(ctx, tx, user.ID()); err != nil {
		return domain.User{}, logger.WrapError(ctx, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("commit change password tx: %w", err))
	}

	return *updatedUser, nil
}

func (r *Repository) VerifyEmailAndAddSession(ctx context.Context, userID uuid.UUID, emailToken domain.EmailVerificationTokenHash, refreshToken domain.RefreshTokenHash) (*domain.User, error) {
	refreshTokenExpiresAt, ok := refreshToken.ExpiresAt()
	if !ok {
		return nil, logger.WrapError(ctx, fmt.Errorf("refresh token expiration is not set"))
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("begin verify email and add session tx: %w", err))
	}
	defer tx.Rollback(ctx)

	verifiedUserID, err := VerifyEmail(ctx, tx, userID, emailToken.Value())
	if err != nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("use email verification token: %w", err))
	}

	if err := VerifyUserEmail(ctx, tx, verifiedUserID); err != nil {
		return nil, logger.WrapError(ctx, err)
	}

	user, err := GetUserByID(ctx, tx, verifiedUserID)
	if err != nil {
		return nil, logger.WrapError(ctx, err)
	}

	if err := AddSessionTx(ctx, tx, verifiedUserID, refreshToken.Value(), refreshTokenExpiresAt); err != nil {
		return nil, logger.WrapError(ctx, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("commit verify email and add session tx: %w", err))
	}

	return user, nil
}
