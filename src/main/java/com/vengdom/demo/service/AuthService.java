package com.vengdom.demo.service;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.vengdom.demo.client.github.GithubEmailResponse;
import com.vengdom.demo.client.github.GithubOAuthClient;
import com.vengdom.demo.client.github.GithubTokenResponse;
import com.vengdom.demo.client.github.GithubUserResponse;
import com.vengdom.demo.dto.AuthResponse;
import com.vengdom.demo.dto.LoginRequest;
import com.vengdom.demo.dto.MfaEnableResponse;
import com.vengdom.demo.dto.RegisterRequest;
import com.vengdom.demo.dto.SessionResponse;
import com.vengdom.demo.dto.UserResponse;
import com.vengdom.demo.entity.RefreshToken;
import com.vengdom.demo.entity.Role;
import com.vengdom.demo.entity.TokenPurpose;
import com.vengdom.demo.entity.User;
import com.vengdom.demo.entity.VerificationToken;
import com.vengdom.demo.exception.DuplicateEmailException;
import com.vengdom.demo.exception.DuplicateUsernameException;
import com.vengdom.demo.exception.InvalidCredentialsException;
import com.vengdom.demo.exception.InvalidRefreshTokenException;
import com.vengdom.demo.exception.InvalidVerificationTokenException;
import com.vengdom.demo.exception.SessionNotFoundException;
import com.vengdom.demo.exception.UserNotFoundException;
import com.vengdom.demo.repository.RefreshTokenRepository;
import com.vengdom.demo.repository.UserRepository;
import com.vengdom.demo.repository.VerificationTokenRepository;
import com.vengdom.demo.security.JwtService;
import com.vengdom.demo.security.TotpService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestClientException;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private static final long PASSWORD_RESET_TOKEN_TTL_MINUTES = 30;
    private static final long EMAIL_VERIFICATION_TOKEN_TTL_MINUTES = 60 * 24;

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final VerificationTokenRepository verificationTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final GoogleIdTokenVerifier googleIdTokenVerifier;
    private final GithubOAuthClient githubOAuthClient;
    private final TotpService totpService;

    @Transactional
    public UserResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new DuplicateEmailException("Email is already registered");
        }
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new DuplicateUsernameException("Username is already taken");
        }

        User user = User.builder()
                .email(request.getEmail())
                .username(request.getUsername())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .verified(false)
                .build();

        // saveAndFlush (not save): @CreationTimestamp/@UpdateTimestamp are only
        // populated on the in-memory entity when the INSERT actually runs, which
        // save() alone defers until transaction commit - too late to read here.
        User saved = userRepository.saveAndFlush(user);

        createVerificationToken(saved, TokenPurpose.EMAIL_VERIFICATION, EMAIL_VERIFICATION_TOKEN_TTL_MINUTES);

        return UserResponse.from(saved);
    }

    @Transactional
    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new InvalidCredentialsException("Invalid email or password"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            throw new InvalidCredentialsException("Invalid email or password");
        }

        return issueTokens(user);
    }

    @Transactional
    public AuthResponse refresh(String refreshTokenValue) {
        RefreshToken stored = refreshTokenRepository.findByToken(refreshTokenValue)
                .orElseThrow(() -> new InvalidRefreshTokenException("Refresh token not recognized"));

        if (stored.isRevoked()) {
            throw new InvalidRefreshTokenException("Refresh token has been revoked");
        }
        if (stored.getExpiresAt().isBefore(LocalDateTime.now()) || !jwtService.isTokenValid(refreshTokenValue)) {
            throw new InvalidRefreshTokenException("Refresh token has expired");
        }

        // Rotation: the presented token is single-use - revoke it and issue a fresh pair.
        stored.setRevoked(true);
        refreshTokenRepository.save(stored);

        return issueTokens(stored.getUser());
    }

    @Transactional
    public void logout(String refreshTokenValue) {
        RefreshToken stored = refreshTokenRepository.findByToken(refreshTokenValue)
                .orElseThrow(() -> new InvalidRefreshTokenException("Refresh token not recognized"));
        stored.setRevoked(true);
        refreshTokenRepository.save(stored);
    }

    @Transactional(readOnly = true)
    public UserResponse getCurrentUser(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User no longer exists"));
        return UserResponse.from(user);
    }

    @Transactional
    public MfaEnableResponse enableMfa(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User no longer exists"));

        String secret = totpService.generateSecret();
        // Stored but not yet active - mfaEnabled only flips to true once the
        // user proves the secret actually works via /auth/mfa/verify, so a
        // botched authenticator-app setup can never lock them out silently.
        user.setMfaSecret(secret);
        userRepository.save(user);

        return MfaEnableResponse.builder()
                .secret(secret)
                .otpAuthUri(totpService.buildOtpAuthUri(secret, user.getEmail()))
                .build();
    }

    @Transactional
    public UserResponse verifyMfa(UUID userId, String code) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User no longer exists"));

        if (user.getMfaSecret() == null) {
            throw new InvalidCredentialsException("MFA has not been set up - call /auth/mfa/enable first");
        }

        if (!totpService.verifyCode(user.getMfaSecret(), code)) {
            throw new InvalidCredentialsException("Invalid MFA code");
        }

        user.setMfaEnabled(true);
        userRepository.save(user);

        return UserResponse.from(user);
    }

    @Transactional(readOnly = true)
    public List<SessionResponse> listSessions(UUID userId) {
        return refreshTokenRepository.findByUserIdAndRevokedFalseAndExpiresAtAfter(userId, LocalDateTime.now())
                .stream()
                .map(SessionResponse::from)
                .toList();
    }

    @Transactional
    public void revokeSession(UUID userId, UUID sessionId) {
        // Scoped by userId at the query level - a 404 here means either the
        // session doesn't exist, belongs to someone else, or is already
        // revoked/expired (i.e. not in the /auth/sessions list anymore).
        // Callers can't tell which - leaking "this ID belongs to another
        // account" would itself be an information disclosure.
        RefreshToken session = refreshTokenRepository
                .findByIdAndUserIdAndRevokedFalseAndExpiresAtAfter(sessionId, userId, LocalDateTime.now())
                .orElseThrow(() -> new SessionNotFoundException("Session not found"));

        session.setRevoked(true);
        refreshTokenRepository.save(session);
    }

    @Transactional
    public void forgotPassword(String email) {
        // Always succeed silently, whether or not the email is registered -
        // otherwise this endpoint becomes a way to enumerate registered accounts.
        userRepository.findByEmail(email)
                .ifPresent(user -> createVerificationToken(user, TokenPurpose.PASSWORD_RESET, PASSWORD_RESET_TOKEN_TTL_MINUTES));
    }

    @Transactional
    public void resetPassword(String token, String newPassword) {
        VerificationToken resetToken = consumeVerificationToken(token, TokenPurpose.PASSWORD_RESET);

        User user = resetToken.getUser();
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // A password reset means any prior session may be compromised - kill them all.
        refreshTokenRepository.deleteByUserId(user.getId());
    }

    @Transactional
    public void verifyEmail(String token) {
        VerificationToken verificationToken = consumeVerificationToken(token, TokenPurpose.EMAIL_VERIFICATION);

        User user = verificationToken.getUser();
        user.setVerified(true);
        userRepository.save(user);
    }

    @Transactional
    public AuthResponse loginWithGoogle(String idTokenString) {
        GoogleIdToken idToken;
        try {
            idToken = googleIdTokenVerifier.verify(idTokenString);
        } catch (GeneralSecurityException | IOException | IllegalArgumentException e) {
            // IllegalArgumentException: the library throws this (not IOException) for
            // a structurally malformed token - e.g. not valid JWT segments at all.
            throw new InvalidCredentialsException("Unable to verify Google ID token");
        }

        if (idToken == null) {
            throw new InvalidCredentialsException("Invalid or expired Google ID token");
        }

        GoogleIdToken.Payload payload = idToken.getPayload();
        String email = payload.getEmail();
        boolean googleVerifiedEmail = Boolean.TRUE.equals(payload.getEmailVerified());

        User user = userRepository.findByEmail(email)
                .map(existing -> {
                    // Google has independently confirmed this email is owned by
                    // whoever is signing in - trust that even for accounts that
                    // registered manually and never finished email verification.
                    if (googleVerifiedEmail && !existing.isVerified()) {
                        existing.setVerified(true);
                        userRepository.save(existing);
                    }
                    return existing;
                })
                .orElseGet(() -> userRepository.saveAndFlush(User.builder()
                        .email(email)
                        .username(generateUniqueUsername(usernameBase(email)))
                        // Google-only accounts never use a local password - a random,
                        // never-revealed hash keeps the column non-null without being guessable.
                        .passwordHash(passwordEncoder.encode(UUID.randomUUID().toString()))
                        .role(Role.USER)
                        .verified(googleVerifiedEmail)
                        .build()));

        return issueTokens(user);
    }

    @Transactional
    public AuthResponse loginWithGithub(String code) {
        GithubTokenResponse tokenResponse;
        try {
            tokenResponse = githubOAuthClient.exchangeCodeForToken(code);
        } catch (RestClientException e) {
            throw new InvalidCredentialsException("Unable to exchange GitHub authorization code");
        }

        // GitHub returns HTTP 200 even for a bad code - errors show up as a
        // populated "error" field, not a non-2xx status, so check explicitly.
        if (tokenResponse == null || tokenResponse.accessToken() == null || tokenResponse.error() != null) {
            log.warn("GitHub code exchange failed: error={}, description={}",
                    tokenResponse == null ? "null response" : tokenResponse.error(),
                    tokenResponse == null ? "null response" : tokenResponse.errorDescription());
            throw new InvalidCredentialsException("Unable to exchange GitHub authorization code");
        }

        GithubUserResponse profile;
        try {
            profile = githubOAuthClient.fetchUser(tokenResponse.accessToken());
        } catch (RestClientException e) {
            throw new InvalidCredentialsException("Unable to fetch GitHub profile");
        }

        String email = profile.email();
        if (email == null || email.isBlank()) {
            // Email is private by default on GitHub - fall back to /user/emails
            // and take the verified primary address.
            List<GithubEmailResponse> emails;
            try {
                emails = githubOAuthClient.fetchEmails(tokenResponse.accessToken());
            } catch (RestClientException e) {
                throw new InvalidCredentialsException("Unable to fetch GitHub email");
            }

            email = emails.stream()
                    .filter(GithubEmailResponse::primary)
                    .filter(GithubEmailResponse::verified)
                    .map(GithubEmailResponse::email)
                    .findFirst()
                    .orElseThrow(() -> new InvalidCredentialsException("GitHub account has no verified email"));
        }

        String resolvedEmail = email;
        User user = userRepository.findByEmail(resolvedEmail)
                .map(existing -> {
                    if (!existing.isVerified()) {
                        existing.setVerified(true);
                        userRepository.save(existing);
                    }
                    return existing;
                })
                .orElseGet(() -> userRepository.saveAndFlush(User.builder()
                        .email(resolvedEmail)
                        .username(generateUniqueUsername(profile.login() != null ? profile.login() : usernameBase(resolvedEmail)))
                        .passwordHash(passwordEncoder.encode(UUID.randomUUID().toString()))
                        .role(Role.USER)
                        // GitHub only returns a verified primary email via the API in
                        // the first place - there's no unverified case to represent here.
                        .verified(true)
                        .build()));

        return issueTokens(user);
    }

    private String usernameBase(String email) {
        return email.substring(0, email.indexOf('@'));
    }

    private String generateUniqueUsername(String preferredBase) {
        String base = preferredBase.replaceAll("[^a-zA-Z0-9]", "");
        if (base.length() < 3) {
            base = base + "user";
        }

        String candidate = base;
        int suffix = 0;
        while (userRepository.existsByUsername(candidate)) {
            suffix++;
            candidate = base + suffix;
        }
        return candidate;
    }

    @Transactional
    public void resendVerification(String email) {
        // Same silent pattern as forgotPassword: no signal either way about
        // whether the email exists or is already verified.
        userRepository.findByEmail(email)
                .filter(user -> !user.isVerified())
                .ifPresent(user -> createVerificationToken(user, TokenPurpose.EMAIL_VERIFICATION, EMAIL_VERIFICATION_TOKEN_TTL_MINUTES));
    }

    private void createVerificationToken(User user, TokenPurpose purpose, long ttlMinutes) {
        String token = UUID.randomUUID().toString();

        VerificationToken verificationToken = VerificationToken.builder()
                .user(user)
                .token(token)
                .purpose(purpose)
                .expiresAt(LocalDateTime.now().plusMinutes(ttlMinutes))
                .used(false)
                .build();
        verificationTokenRepository.save(verificationToken);

        // No email provider is wired up yet - log the token so it's usable for
        // manual testing. Replace with a real email send when one exists.
        log.info("{} token for {}: {}", purpose, user.getEmail(), token);
    }

    private VerificationToken consumeVerificationToken(String token, TokenPurpose purpose) {
        VerificationToken verificationToken = verificationTokenRepository.findByTokenAndPurpose(token, purpose)
                .orElseThrow(() -> new InvalidVerificationTokenException("Token not recognized"));

        if (verificationToken.isUsed()) {
            throw new InvalidVerificationTokenException("Token has already been used");
        }
        if (verificationToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new InvalidVerificationTokenException("Token has expired");
        }

        verificationToken.setUsed(true);
        verificationTokenRepository.save(verificationToken);

        return verificationToken;
    }

    private AuthResponse issueTokens(User user) {
        String accessToken = jwtService.generateAccessToken(user);
        String refreshTokenValue = jwtService.generateRefreshToken(user);

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(refreshTokenValue)
                .expiresAt(LocalDateTime.now().plus(Duration.ofMillis(jwtService.getRefreshTokenExpirationMs())))
                .revoked(false)
                .build();
        refreshTokenRepository.save(refreshToken);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshTokenValue)
                .build();
    }
}
