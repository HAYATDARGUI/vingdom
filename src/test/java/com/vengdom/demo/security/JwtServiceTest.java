package com.vengdom.demo.security;

import com.vengdom.demo.entity.Role;
import com.vengdom.demo.entity.User;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtServiceTest {

    private static final String SECRET = "JMJSu0Hscj4rVwLC9GHMBxTyzwS7DBssYpB9PwivBIg=";

    private final JwtService jwtService = new JwtService(SECRET, 900_000, 604_800_000);

    private User sampleUser() {
        return User.builder()
                .id(UUID.randomUUID())
                .email("jwt-test@vingdom.dev")
                .username("jwttester")
                .role(Role.USER)
                .build();
    }

    @Test
    void generatedAccessToken_isValid_andCarriesExpectedClaims() {
        User user = sampleUser();

        String token = jwtService.generateAccessToken(user);

        assertThat(jwtService.isTokenValid(token)).isTrue();
        assertThat(jwtService.extractUserId(token)).isEqualTo(user.getId());
        assertThat(jwtService.extractEmail(token)).isEqualTo(user.getEmail());
        assertThat(jwtService.extractRole(token)).isEqualTo("USER");
        assertThat(jwtService.extractAllClaims(token).get("type", String.class)).isEqualTo("access");
    }

    @Test
    void generatedRefreshToken_isValid_andMarkedAsRefreshType() {
        User user = sampleUser();

        String token = jwtService.generateRefreshToken(user);

        assertThat(jwtService.isTokenValid(token)).isTrue();
        assertThat(jwtService.extractUserId(token)).isEqualTo(user.getId());
        assertThat(jwtService.extractAllClaims(token).get("type", String.class)).isEqualTo("refresh");
    }

    @Test
    void twoTokensForSameUser_areNeverIdentical() {
        User user = sampleUser();

        String first = jwtService.generateAccessToken(user);
        String second = jwtService.generateAccessToken(user);

        assertThat(first).isNotEqualTo(second);
    }

    @Test
    void expiredToken_isRejected() throws InterruptedException {
        JwtService shortLivedJwtService = new JwtService(SECRET, 1, 1);
        String token = shortLivedJwtService.generateAccessToken(sampleUser());

        Thread.sleep(50);

        assertThat(shortLivedJwtService.isTokenValid(token)).isFalse();
        assertThatThrownBy(() -> shortLivedJwtService.extractAllClaims(token))
                .isInstanceOf(io.jsonwebtoken.ExpiredJwtException.class);
    }

    @Test
    void tamperedToken_isRejected() {
        String token = jwtService.generateAccessToken(sampleUser());
        String tampered = token.substring(0, token.length() - 4) + "abcd";

        assertThat(jwtService.isTokenValid(tampered)).isFalse();
    }

    @Test
    void tokenSignedWithDifferentSecret_isRejected() {
        JwtService otherService = new JwtService(
                "7ZzXrLDhu6w4816OFaoCXwqZstrH1AjJ4sFd2UmT0r0=", 900_000, 604_800_000);
        String token = otherService.generateAccessToken(sampleUser());

        assertThat(jwtService.isTokenValid(token)).isFalse();
    }

    @Test
    void malformedToken_isRejected() {
        assertThat(jwtService.isTokenValid("not-a-jwt-at-all")).isFalse();
    }
}
