package com.vengdom.demo.repository;

import com.vengdom.demo.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByToken(String token);

    void deleteByUserId(UUID userId);

    List<RefreshToken> findByUserIdAndRevokedFalseAndExpiresAtAfter(UUID userId, LocalDateTime now);

    // Scoped by userId (never lookup-able by ID alone) AND to currently-active
    // sessions, so revoking something already revoked/expired - i.e. not in
    // the /auth/sessions list anymore - correctly 404s instead of no-op succeeding.
    Optional<RefreshToken> findByIdAndUserIdAndRevokedFalseAndExpiresAtAfter(UUID id, UUID userId, LocalDateTime now);
}
