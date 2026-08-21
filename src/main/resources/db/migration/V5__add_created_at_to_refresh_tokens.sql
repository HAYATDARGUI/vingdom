ALTER TABLE refresh_tokens
    ADD COLUMN created_at TIMESTAMP NOT NULL DEFAULT now();
