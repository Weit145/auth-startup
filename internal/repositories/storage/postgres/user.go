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

func (r *Repository) CreateEmailVerificationToken(ctx context.Context, email string, token domain.EmailVerificationTokenHash) (domain.User, error) {
	tokenExpiresAt, ok := token.ExpiresAt()
	if !ok {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("email verification token expiration is not set"))
	}

	pendingUser, err := domain.NewUser(uuid.New(), email, "user")
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("create pending user: %w", err))
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("begin registration request tx: %w", err))
	}
	defer tx.Rollback(ctx)

	const insertUserStmt = `
		INSERT INTO users (id, email, password_hash, role)
		VALUES ($1, $2, NULL, $3)
		ON CONFLICT (email) DO NOTHING
		RETURNING id, email, role
	`

	var result domain.User
	var id uuid.UUID
	var emailDB, role string
	err = tx.QueryRow(ctx, insertUserStmt, pendingUser.ID(), pendingUser.Email(), pendingUser.Role()).
		Scan(&id, &emailDB, &role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, logger.WrapError(ctx, fmt.Errorf("create pending user: %w", errs.ErrAlreadyExists))
		}
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("create pending user: %w", err))
	}

	createdUser, err := domain.NewUser(id, emailDB, role)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("build pending user: %w", err))
	}
	result = *createdUser

	if err := AddEmailVerificationToken(ctx, tx, result.ID(), token.Value(), tokenExpiresAt); err != nil {
		return domain.User{}, logger.WrapError(ctx, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("commit registration request tx: %w", err))
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

	const invalidateRegistrationSessionsStmt = `
		UPDATE registration_sessions
		SET used_at = now()
		WHERE user_id = $1 AND used_at IS NULL
	`
	if _, err := tx.Exec(ctx, invalidateRegistrationSessionsStmt, user.ID()); err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("invalidate registration sessions: %w", err))
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

func (r *Repository) GetUserByEmail(ctx context.Context, email string) (*domain.Account, error) {
	query := `
		SELECT id, email, password_hash, role, email_verified_at
		FROM users
		WHERE email = $1
			AND email_verified_at IS NOT NULL
			AND password_hash IS NOT NULL
	`
	var (
		id              uuid.UUID
		emailDB         string
		passwordHash    string
		role            string
		emailVerifiedAt time.Time
	)

	err := r.db.QueryRow(ctx, query, email).Scan(&id, &emailDB, &passwordHash, &role, &emailVerifiedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, logger.WrapError(ctx, errs.ErrNotFound)
		}
		return nil, logger.WrapError(ctx, fmt.Errorf("query user by email: %w", err))
	}

	result, err := domain.CreateUserAccount(id, emailDB, passwordHash, role, &emailVerifiedAt)
	if err != nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("build user from database row: %w", err))
	}

	return result, nil
}

func GetPendingUserByID(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (*domain.User, error) {
	query := `
			SELECT id, email, role
			FROM users
			WHERE id = $1
				AND email_verified_at IS NULL
		`
	var (
		id      uuid.UUID
		emailDB string
		role    string
	)

	err := tx.QueryRow(ctx, query, userID).Scan(&id, &emailDB, &role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, logger.WrapError(ctx, errs.ErrNotFound)
		}
		return nil, logger.WrapError(ctx, fmt.Errorf("query user by id: %w", err))
	}

	result, err := domain.NewUser(id, emailDB, role)
	if err != nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("build user from database row: %w", err))
	}

	return result, nil
}

func GetUnverifiedUserByEmail(ctx context.Context, tx pgx.Tx, email string) (*domain.User, error) {
	query := `
		SELECT id, email, role
		FROM users
		WHERE email = $1 AND email_verified_at IS NULL
		FOR UPDATE
	`
	var (
		id      uuid.UUID
		emailDB string
		role    string
	)

	err := tx.QueryRow(ctx, query, email).Scan(&id, &emailDB, &role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, logger.WrapError(ctx, errs.ErrNotFound)
		}
		return nil, logger.WrapError(ctx, fmt.Errorf("query unverified user by email: %w", err))
	}

	result, err := domain.NewUser(id, emailDB, role)
	if err != nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("build user from database row: %w", err))
	}

	return result, nil
}

func GetVerifiedUserByEmail(ctx context.Context, tx pgx.Tx, email string) (*domain.User, error) {
	query := `
		SELECT id, email, role
		FROM users
		WHERE email = $1 AND email_verified_at IS NOT NULL
		FOR UPDATE
	`
	var (
		id      uuid.UUID
		emailDB string
		role    string
	)

	err := tx.QueryRow(ctx, query, email).Scan(&id, &emailDB, &role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, logger.WrapError(ctx, errs.ErrNotFound)
		}
		return nil, logger.WrapError(ctx, fmt.Errorf("query verified user by email: %w", err))
	}

	result, err := domain.NewUser(id, emailDB, role)
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
		RETURNING id, email, role
	`
	var (
		id    uuid.UUID
		email string
		role  string
	)

	err := tx.QueryRow(ctx, query, userID, passwordHash).Scan(&id, &email, &role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, logger.WrapError(ctx, errs.ErrNotFound)
		}
		return nil, logger.WrapError(ctx, fmt.Errorf("update user password: %w", err))
	}

	result, err := domain.NewUser(id, email, role)
	if err != nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("build user from database row: %w", err))
	}

	return result, nil
}

func GetVerifiedUserWithActiveSession(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (*domain.User, string, error) {
	query := `
		SELECT u.id, u.email, u.role, u.password_hash
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
		role         string
		passwordHash string
	)

	err := tx.QueryRow(ctx, query, userID).Scan(&id, &email, &role, &passwordHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", logger.WrapError(ctx, errs.ErrUnauthorized)
		}
		return nil, "", logger.WrapError(ctx, fmt.Errorf("query user with active session: %w", err))
	}

	result, err := domain.NewUser(id, email, role)
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

func (r *Repository) VerifyEmailAndAddShortSession(
	ctx context.Context,
	userID uuid.UUID,
	shortSessionToken domain.ShortSessionTokenHash,
	emailToken domain.EmailVerificationTokenHash,
) (domain.User, uuid.UUID, error) {
	shortSessionExpiresAt, ok := shortSessionToken.ExpiresAt()
	if !ok {
		return domain.User{}, uuid.Nil, logger.WrapError(ctx, fmt.Errorf("short session expiration is not set"))
	}
	if shortSessionToken.ID() == uuid.Nil {
		return domain.User{}, uuid.Nil, logger.WrapError(ctx, fmt.Errorf("short session id is not set: %w", errs.ErrInvalidInput))
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return domain.User{}, uuid.Nil, logger.WrapError(ctx, fmt.Errorf("begin verify email tx: %w", err))
	}
	defer tx.Rollback(ctx)

	verifiedUserID, err := VerifyEmail(ctx, tx, userID, emailToken.Value())
	if err != nil {
		return domain.User{}, uuid.Nil, logger.WrapError(ctx, fmt.Errorf("use email verification token: %w", err))
	}

	user, err := GetPendingUserByID(ctx, tx, verifiedUserID)
	if err != nil {
		return domain.User{}, uuid.Nil, logger.WrapError(ctx, err)
	}

	const invalidateSessionsStmt = `
		UPDATE registration_sessions
		SET used_at = now()
		WHERE user_id = $1 AND used_at IS NULL
	`
	if _, err := tx.Exec(ctx, invalidateSessionsStmt, verifiedUserID); err != nil {
		return domain.User{}, uuid.Nil, logger.WrapError(ctx, fmt.Errorf("invalidate registration sessions: %w", err))
	}

	const addSessionStmt = `
		INSERT INTO registration_sessions (id, user_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
	`
	if _, err := tx.Exec(
		ctx,
		addSessionStmt,
		shortSessionToken.ID(),
		verifiedUserID,
		shortSessionToken.Value(),
		shortSessionExpiresAt,
	); err != nil {
		return domain.User{}, uuid.Nil, logger.WrapError(ctx, fmt.Errorf("insert registration session: %w", err))
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, uuid.Nil, logger.WrapError(ctx, fmt.Errorf("commit verify email tx: %w", err))
	}

	return *user, shortSessionToken.ID(), nil
}

func (r *Repository) CompleteRegistration(
	ctx context.Context,
	sessionID uuid.UUID,
	passwordHash string,
	refreshToken domain.RefreshTokenHash,
) (domain.User, error) {
	refreshTokenExpiresAt, ok := refreshToken.ExpiresAt()
	if !ok {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("refresh token expiration is not set"))
	}
	if sessionID == uuid.Nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("registration session id is not set: %w", errs.ErrInvalidInput))
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("begin complete registration tx: %w", err))
	}
	defer tx.Rollback(ctx)

	const consumeSessionStmt = `
		UPDATE registration_sessions
		SET used_at = now()
		WHERE id = $1
			AND used_at IS NULL
			AND expires_at > now()
		RETURNING user_id
	`
	var userID uuid.UUID
	if err := tx.QueryRow(ctx, consumeSessionStmt, sessionID).Scan(&userID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, logger.WrapError(ctx, errs.ErrUnauthorized)
		}
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("consume registration session: %w", err))
	}

	const completeUserStmt = `
		UPDATE users
		SET password_hash = $2,
			email_verified_at = now()
		WHERE id = $1
			AND email_verified_at IS NULL
		RETURNING id, email, role
	`
	var id uuid.UUID
	var email, role string
	if err := tx.QueryRow(ctx, completeUserStmt, userID, passwordHash).Scan(&id, &email, &role); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, logger.WrapError(ctx, errs.ErrAlreadyExists)
		}
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("complete user account: %w", err))
	}

	user, err := domain.NewUser(id, email, role)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("build completed user: %w", err))
	}

	if err := AddSessionTx(ctx, tx, user.ID(), refreshToken.Value(), refreshTokenExpiresAt); err != nil {
		return domain.User{}, logger.WrapError(ctx, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("commit complete registration tx: %w", err))
	}

	return *user, nil
}
