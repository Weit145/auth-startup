# Auth Service Notes

## TODO: Secure Repeated Registration

Current registration behavior updates the password and name when an unverified
account with the same email already exists:

```sql
ON CONFLICT (email) DO UPDATE
SET
    password_hash = EXCLUDED.password_hash,
    name = EXCLUDED.name
WHERE users.email_verified_at IS NULL
```

This is unsafe because the service cannot distinguish the email owner from an
attacker.

### Attack Scenario

1. The owner registers `owner@example.com`.
2. An attacker registers the same email using the attacker's password.
3. The database replaces the pending account password.
4. The owner opens the new verification email and confirms the account.
5. The attacker can log in using the password they selected.

Password recovery or support can restore the account later, but they do not
prevent the initial account takeover.

### Minimum Safe Fix

Do not update an existing account during registration:

```sql
INSERT INTO users (id, email, password_hash, name, role)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (email) DO NOTHING
RETURNING id, email, name, role;
```

When no row is returned, return `ErrAlreadyExists`. Do not change the existing
password, name, or verification token.

### Future Options

- Add a separate resend-verification endpoint with rate limiting.
- Add password reset using a one-time token sent to the email owner.
- Store registrations in a separate `pending_registrations` table and create
  users only after email confirmation.


Если auth gRPC используется не только локально, его нельзя публиковать наружу без TLS/mTLS и rate limiting.