package com.vengdom.demo.dto;

import com.vengdom.demo.entity.RefreshToken;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SessionResponse {

    private UUID id;
    private LocalDateTime createdAt;
    private LocalDateTime expiresAt;

    // Deliberately excludes the raw refresh token value - a session listing
    // should never leak the actual bearer credential for that session.
    public static SessionResponse from(RefreshToken refreshToken) {
        return SessionResponse.builder()
                .id(refreshToken.getId())
                .createdAt(refreshToken.getCreatedAt())
                .expiresAt(refreshToken.getExpiresAt())
                .build();
    }
}
