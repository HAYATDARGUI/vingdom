package com.vengdom.demo.client.github;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;

@Component
public class GithubOAuthClient {

    private final RestClient restClient = RestClient.create();
    private final String clientId;
    private final String clientSecret;

    public GithubOAuthClient(
            @Value("${github.oauth.client-id}") String clientId,
            @Value("${github.oauth.client-secret}") String clientSecret) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    public GithubTokenResponse exchangeCodeForToken(String code) {
        return restClient.post()
                .uri("https://github.com/login/oauth/access_token")
                .header("Accept", "application/json")
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of(
                        "client_id", clientId,
                        "client_secret", clientSecret,
                        "code", code
                ))
                .retrieve()
                .body(GithubTokenResponse.class);
    }

    public GithubUserResponse fetchUser(String accessToken) {
        return restClient.get()
                .uri("https://api.github.com/user")
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/vnd.github+json")
                .retrieve()
                .body(GithubUserResponse.class);
    }

    public List<GithubEmailResponse> fetchEmails(String accessToken) {
        return restClient.get()
                .uri("https://api.github.com/user/emails")
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/vnd.github+json")
                .retrieve()
                .body(new ParameterizedTypeReference<List<GithubEmailResponse>>() {
                });
    }
}
