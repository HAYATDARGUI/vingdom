package com.vengdom.demo.controller;

import com.vengdom.demo.dto.AuthResponse;
import com.vengdom.demo.dto.ForgotPasswordRequest;
import com.vengdom.demo.dto.GithubAuthRequest;
import com.vengdom.demo.dto.GoogleAuthRequest;
import com.vengdom.demo.dto.LoginRequest;
import com.vengdom.demo.dto.MfaEnableResponse;
import com.vengdom.demo.dto.MfaVerifyRequest;
import com.vengdom.demo.dto.RefreshTokenRequest;
import com.vengdom.demo.dto.RegisterRequest;
import com.vengdom.demo.dto.ResendVerificationRequest;
import com.vengdom.demo.dto.ResetPasswordRequest;
import com.vengdom.demo.dto.SessionResponse;
import com.vengdom.demo.dto.UserResponse;
import com.vengdom.demo.dto.VerifyEmailRequest;
import com.vengdom.demo.service.AuthService;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refresh(request.getRefreshToken()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody RefreshTokenRequest request) {
        authService.logout(request.getRefreshToken());
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/me")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<UserResponse> me(@AuthenticationPrincipal UUID userId) {
        return ResponseEntity.ok(authService.getCurrentUser(userId));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<Void> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        authService.forgotPassword(request.getEmail());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Void> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        authService.resetPassword(request.getToken(), request.getNewPassword());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/verify-email")
    public ResponseEntity<Void> verifyEmail(@Valid @RequestBody VerifyEmailRequest request) {
        authService.verifyEmail(request.getToken());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<Void> resendVerification(@Valid @RequestBody ResendVerificationRequest request) {
        authService.resendVerification(request.getEmail());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/oauth/google")
    public ResponseEntity<AuthResponse> googleOAuth(@Valid @RequestBody GoogleAuthRequest request) {
        return ResponseEntity.ok(authService.loginWithGoogle(request.getIdToken()));
    }

    @PostMapping("/oauth/github")
    public ResponseEntity<AuthResponse> githubOAuth(@Valid @RequestBody GithubAuthRequest request) {
        return ResponseEntity.ok(authService.loginWithGithub(request.getCode()));
    }

    @PostMapping("/mfa/enable")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<MfaEnableResponse> enableMfa(@AuthenticationPrincipal UUID userId) {
        return ResponseEntity.ok(authService.enableMfa(userId));
    }

    @PostMapping("/mfa/verify")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<UserResponse> verifyMfa(@AuthenticationPrincipal UUID userId, @Valid @RequestBody MfaVerifyRequest request) {
        return ResponseEntity.ok(authService.verifyMfa(userId, request.getCode()));
    }

    @GetMapping("/sessions")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<List<SessionResponse>> listSessions(@AuthenticationPrincipal UUID userId) {
        return ResponseEntity.ok(authService.listSessions(userId));
    }

    @DeleteMapping("/sessions/{sessionId}")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<Void> revokeSession(@AuthenticationPrincipal UUID userId, @PathVariable UUID sessionId) {
        authService.revokeSession(userId, sessionId);
        return ResponseEntity.noContent().build();
    }
}
