CREATE TABLE verification_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token      VARCHAR(255) NOT NULL UNIQUE,
    purpose    VARCHAR(30) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used       BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_verification_tokens_user_id ON verification_tokens (user_id);
CREATE INDEX idx_verification_tokens_token ON verification_tokens (token);
