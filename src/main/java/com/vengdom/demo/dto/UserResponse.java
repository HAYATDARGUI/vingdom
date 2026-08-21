package com.vengdom.demo.dto;

import com.vengdom.demo.entity.Role;
import com.vengdom.demo.entity.User;
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
public class UserResponse {

    private UUID id;
    private String email;
    private String username;
    private Role role;
    private boolean verified;
    private boolean mfaEnabled;
    private LocalDateTime createdAt;

    public static UserResponse from(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .username(user.getUsername())
                .role(user.getRole())
                .verified(user.isVerified())
                .mfaEnabled(user.isMfaEnabled())
                .createdAt(user.getCreatedAt())
                .build();
    }
}
