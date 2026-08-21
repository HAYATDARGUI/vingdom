package com.vengdom.demo.client.github;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record GithubUserResponse(
        Long id,
        String login,
        String email,
        String name
) {
}
