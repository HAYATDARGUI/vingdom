package com.vengdom.demo.client.github;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * GitHub's token endpoint returns HTTP 200 even for a bad/expired code -
 * failures show up as a populated "error" field, not a non-2xx status.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GithubTokenResponse(
        @JsonProperty("access_token") String accessToken,
        @JsonProperty("token_type") String tokenType,
        String scope,
        String error,
        @JsonProperty("error_description") String errorDescription
) {
}
