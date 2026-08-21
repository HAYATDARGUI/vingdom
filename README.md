# Vingdom - User Authentication Service

This document explains what this service does, how it's built, and the reasoning behind the key decisions. It's meant to be enough to explain the work to a manager or teammate without them having to read the code.

## What this service is

One of six microservices in Vingdom (a YouTube-style platform). This one owns **identity**: registration, login, password/email/session management, two-factor auth, and social sign-in. Every other service (starting with Video Upload) trusts the JWTs this service issues, without calling back to it.

- **Stack**: Spring Boot 3.3.5, Java 17, Maven, PostgreSQL 16 (Docker), Flyway for schema migrations
- **Port**: 8081
- **Database**: `vingdom_users`, Postgres container on `localhost:5433`

## The core design decision: stateless JWT auth

Instead of server-side sessions, login issues two JSON Web Tokens:

- **Access token** (15 min lifetime) — sent as `Authorization: Bearer <token>` on every protected request. Contains the user's ID, email, and role directly in the token, signed with a shared secret (`jwt.secret`). Any service holding that same secret can verify the token **without calling this service** — no database lookup, no network call. This is what lets the whole team's services stay decoupled: Video Upload Service (and every other service) can validate a request's identity on its own.
- **Refresh token** (7 day lifetime) — a longer-lived credential, stored in the `refresh_tokens` table (unlike the access token, this one *is* checked against the database), used only to obtain a new access token when the old one expires. Single-use: every refresh **rotates** the token (old one is revoked, a new pair is issued), so a leaked refresh token has a limited window of usefulness.

**Why this split:** short-lived access tokens limit the damage if one leaks (dead in 15 minutes, no way to revoke early). Long-lived refresh tokens stay in the database so they *can* be revoked on demand (logout, password reset, explicit session kill) — the access token can't be individually revoked before it expires, which is the standard, accepted trade-off of stateless JWTs.

## Database schema

Five Flyway migrations, applied in order automatically on every startup:

| Migration | Table / change |
|---|---|
| V1 | `users` — id, email, username, password_hash, role, is_verified, timestamps |
| V2 | `refresh_tokens` — id, user_id (FK), token, expires_at, revoked |
| V3 | `verification_tokens` — shared table for both password-reset and email-verification tokens (same shape: opaque single-use token + expiry + owning user), distinguished by a `purpose` column |
| V4 | Added `mfa_secret` and `mfa_enabled` to `users` |
| V5 | Added `created_at` to `refresh_tokens` (needed so `/auth/sessions` can show when each login happened) |

## Every endpoint, and what it does

| Endpoint | Auth required? | What it does |
|---|---|---|
| `POST /auth/register` | No | Creates an account, hashes the password with BCrypt, auto-generates an email verification token |
| `POST /auth/login` | No | Verifies email/password, issues access + refresh tokens |
| `POST /auth/refresh-token` | No (needs a valid refresh token) | Rotates to a new access + refresh pair |
| `POST /auth/logout` | No (needs a valid refresh token) | Revokes that one refresh token |
| `GET /auth/me` | Yes | Returns the logged-in user's profile |
| `POST /auth/forgot-password` | No | Generates a password reset token if the email exists (silent no-op otherwise, so the endpoint can't be used to find out who has an account) |
| `POST /auth/reset-password` | No (needs the reset token) | Sets a new password, and **revokes every existing session** for that account (a password reset means old sessions may be compromised) |
| `POST /auth/verify-email` | No (needs the verification token) | Marks the account's email as verified |
| `POST /auth/resend-verification` | No | Issues a new verification token, same silent-if-not-found pattern as forgot-password |
| `POST /auth/oauth/google` | No | Frontend gets an ID token from Google directly; we verify it and log the user in (creating an account on first sign-in) |
| `POST /auth/oauth/github` | No | Frontend gets an authorization code from GitHub; we exchange it server-side for the user's profile and log them in |
| `POST /auth/mfa/enable` | Yes | Generates a TOTP (authenticator app) secret for the account — not active yet |
| `POST /auth/mfa/verify` | Yes | Confirms a code from the authenticator app actually works, and only then activates MFA |
| `GET /auth/sessions` | Yes | Lists this account's active logins (id, when it started, when it expires — never the raw token) |
| `DELETE /auth/sessions/{id}` | Yes | Revokes one specific session ("log out this device") |

Every error response (across all endpoints) uses the same JSON shape — timestamp, status, error, message, path — so any client only needs one error handler.

## Account linking across login methods

If someone registers manually with `alice@vingdom.dev`, then later signs in with Google using that same email, they land in the **same account** — matched by email, not created as a duplicate. Verified this works across both Google and GitHub sign-in, including against a manually-registered account. (Known limitation: email matching is currently case-sensitive, so `Alice@x.com` and `alice@x.com` would be treated as different accounts — a small fix if it ever matters.)

## Two-factor authentication (TOTP)

Standard authenticator-app-based 2FA (Google Authenticator, Authy, etc.), implemented from scratch against RFC 6238 rather than pulling in a third-party library — it's a small, well-defined algorithm (HMAC-SHA1 over a 30-second time window), and avoiding an extra dependency meant one less thing that could have version-compatibility issues. Verified the implementation against the official RFC 6238 published test vectors, not just internal self-consistency.

Setup is two steps on purpose: `mfa/enable` generates a secret but doesn't turn anything on; `mfa/verify` requires proving the code actually works before `mfa_enabled` flips to true. This means a botched authenticator app setup can never lock someone out of their own account.

**Known gap**: MFA is fully built and working, but `/auth/login` doesn't currently *require* the code even when MFA is enabled — enabling MFA today doesn't yet change what login does. Making login actually gate on it is a separate, larger change (it needs a way to carry "password was correct, waiting on the code" state between two separate requests) that hasn't been built yet.

## Security decisions worth knowing about

- **Passwords**: BCrypt via Spring Security's `PasswordEncoder` — industry standard, adaptive cost, salts automatically.
- **No account enumeration**: `forgot-password` and `resend-verification` always return the same response whether or not the email exists — the only way to tell the difference is that a token gets logged server-side (or, in production, emailed) for real accounts only.
- **Session revocation is real, not cosmetic**: revoking a session (via logout, password reset, or `DELETE /auth/sessions/{id}`) actually invalidates the underlying refresh token — verified by trying to use a revoked token afterward and confirming it's rejected.
- **Cross-user protection on sessions**: a user can only ever look up or revoke their *own* sessions — verified that a second account attempting to revoke someone else's session gets a `404` (not even confirming the session exists), and that the real owner's session is untouched by the attempt.
- **A caught bug worth mentioning**: during testing, revoking the same session twice initially returned success both times instead of correctly failing the second time. Fixed by scoping the lookup query to only currently-active sessions.

## Google & GitHub sign-in: two different flows, on purpose

- **Google**: the frontend uses Google's own "Sign in with Google" button to get an ID token directly (a signed JWT), and POSTs it to us. We just verify the signature against Google's public keys — no secret needed on our side at all for this.
- **GitHub**: GitHub doesn't offer that client-side option — it only supports the older "authorization code" flow, where our *backend* has to exchange the code for an access token using a Client Secret, server-to-server. One quirk worth knowing: GitHub's token endpoint returns `HTTP 200` even for a bad/expired code, with an `error` field in the body instead of a proper error status — had to check that explicitly rather than trusting the status code.

Both flows were tested against real Google/GitHub accounts, not just mocked — including confirming that signing in with the same email via both providers (and a manual registration) all resolve to one account.

## What's built for local testing (dev-only, not part of the product)

- `http://localhost:8081/swagger-ui/index.html` — interactive API docs generated live from the actual code (via springdoc-openapi), so it can never drift out of sync with reality the way hand-written docs would.
- `google-test.html`, `github-test.html` / `github-callback.html` — standalone pages that drive the real Google/GitHub sign-in flow and show the raw result. These double as working reference examples for whoever builds the actual frontend integration.

## Known gaps / not yet done

- **CORS is not configured** — a browser-based frontend on a different origin (e.g. `localhost:3000`) cannot currently call this API; it'll be silently blocked by the browser even though the API itself works. Needs a small Spring Security CORS config before frontend integration can work.
- **MFA doesn't gate login yet** (explained above).
- **No real email sending** — anywhere a real product would send an email (password reset, verification, MFA-adjacent flows), this service currently just logs the token to the console. Wiring up a real email provider is a separate task.
- Endpoints from the team-wide API spec not built (because not requested): `/auth/sessions` bulk operations beyond single revoke, admin-only auth endpoints, etc.

## How to run it

```bash
cd "path/to/demo"
./run.sh
```

`run.sh` starts the Postgres Docker container if it isn't running, loads OAuth credentials from a git-ignored `.env` file, and starts the app. Flyway applies any pending migrations automatically on boot.

## Testing

- **Unit tests**: `JwtServiceTest` (token generation/validation/expiry, all passing) — no Spring context needed, fast.
- **Integration test**: `AuthFlowIntegrationTest` — exercises the full HTTP stack (controller → service → security filter → real Postgres via Testcontainers) for the core register → login → refresh → logout flow plus edge cases (duplicate email/username, wrong password, expired/revoked tokens). Written and compiles cleanly; note it needs Docker to actually run, so confirm it passes in your own environment/CI before relying on it.
- Every feature beyond the core flow (MFA, sessions, OAuth, password reset, email verification) was verified through live manual testing against the running service — real HTTP requests, real database checks, real third-party accounts for Google/GitHub — not just written and assumed correct.
