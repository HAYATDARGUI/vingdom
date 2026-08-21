package com.vengdom.demo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vengdom.demo.dto.LoginRequest;
import com.vengdom.demo.dto.RefreshTokenRequest;
import com.vengdom.demo.dto.RegisterRequest;
import com.vengdom.demo.entity.User;
import com.vengdom.demo.repository.RefreshTokenRepository;
import com.vengdom.demo.repository.UserRepository;
import com.vengdom.demo.security.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Exercises the real HTTP stack (controller -> service -> security filter ->
 * database) against an ephemeral Postgres container - the same migrations and
 * the same security chain that run in production, just pointed at a throwaway DB.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class AuthFlowIntegrationTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @BeforeEach
    void cleanDatabase() {
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    void fullAuthFlow_registerLoginMeRefreshLogout() throws Exception {
        RegisterRequest register = RegisterRequest.builder()
                .email("carol@vingdom.dev")
                .username("carol")
                .password("supersecret1")
                .build();

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(register)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value("carol@vingdom.dev"))
                .andExpect(jsonPath("$.verified").value(false))
                .andExpect(jsonPath("$.createdAt").exists());

        LoginRequest login = LoginRequest.builder().email("carol@vingdom.dev").password("supersecret1").build();

        String loginBody = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(login)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andReturn().getResponse().getContentAsString();

        JsonNode tokens = objectMapper.readTree(loginBody);
        String accessToken = tokens.get("accessToken").asText();
        String refreshToken = tokens.get("refreshToken").asText();

        mockMvc.perform(get("/auth/me").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("carol"));

        String refreshBody = mockMvc.perform(post("/auth/refresh-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                RefreshTokenRequest.builder().refreshToken(refreshToken).build())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.refreshToken").value(not(refreshToken)))
                .andReturn().getResponse().getContentAsString();

        String newRefreshToken = objectMapper.readTree(refreshBody).get("refreshToken").asText();

        // rotation: the old refresh token must now be rejected
        mockMvc.perform(post("/auth/refresh-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                RefreshTokenRequest.builder().refreshToken(refreshToken).build())))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                RefreshTokenRequest.builder().refreshToken(newRefreshToken).build())))
                .andExpect(status().isNoContent());

        // after logout, the (rotated) refresh token must be rejected too
        mockMvc.perform(post("/auth/refresh-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                RefreshTokenRequest.builder().refreshToken(newRefreshToken).build())))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void register_duplicateEmail_returns409() throws Exception {
        registerUser("dave@vingdom.dev", "dave", "password123");

        RegisterRequest duplicate = RegisterRequest.builder()
                .email("dave@vingdom.dev")
                .username("dave2")
                .password("password123")
                .build();

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(duplicate)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Email is already registered"));
    }

    @Test
    void register_duplicateUsername_returns409() throws Exception {
        registerUser("erin@vingdom.dev", "erin", "password123");

        RegisterRequest duplicate = RegisterRequest.builder()
                .email("erin2@vingdom.dev")
                .username("erin")
                .password("password123")
                .build();

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(duplicate)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Username is already taken"));
    }

    @Test
    void login_wrongPassword_returns401() throws Exception {
        registerUser("frank@vingdom.dev", "frank", "password123");

        LoginRequest badLogin = LoginRequest.builder()
                .email("frank@vingdom.dev")
                .password("totally-wrong")
                .build();

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(badLogin)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid email or password"));
    }

    @Test
    void protectedRoute_withoutToken_returns401() throws Exception {
        mockMvc.perform(get("/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void protectedRoute_withExpiredAccessToken_returns401() throws Exception {
        User user = registerUser("grace@vingdom.dev", "grace", "password123");

        JwtService shortLivedJwtService = new JwtService(
                "JMJSu0Hscj4rVwLC9GHMBxTyzwS7DBssYpB9PwivBIg=", 1, 1);
        String expiredToken = shortLivedJwtService.generateAccessToken(user);
        Thread.sleep(50);

        mockMvc.perform(get("/auth/me").header("Authorization", "Bearer " + expiredToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void refresh_withRevokedToken_returns401() throws Exception {
        registerUser("henry@vingdom.dev", "henry", "password123");

        String loginBody = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                LoginRequest.builder().email("henry@vingdom.dev").password("password123").build())))
                .andReturn().getResponse().getContentAsString();

        String refreshToken = objectMapper.readTree(loginBody).get("refreshToken").asText();

        mockMvc.perform(post("/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                RefreshTokenRequest.builder().refreshToken(refreshToken).build())))
                .andExpect(status().isNoContent());

        mockMvc.perform(post("/auth/refresh-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                RefreshTokenRequest.builder().refreshToken(refreshToken).build())))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Refresh token has been revoked"));
    }

    private User registerUser(String email, String username, String rawPassword) throws Exception {
        RegisterRequest request = RegisterRequest.builder()
                .email(email)
                .username(username)
                .password(rawPassword)
                .build();

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated());

        return userRepository.findByEmail(email).orElseThrow();
    }
}
