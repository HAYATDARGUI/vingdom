package com.vengdom.demo.repository;

import com.vengdom.demo.entity.TokenPurpose;
import com.vengdom.demo.entity.VerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface VerificationTokenRepository extends JpaRepository<VerificationToken, UUID> {

    Optional<VerificationToken> findByTokenAndPurpose(String token, TokenPurpose purpose);
}
