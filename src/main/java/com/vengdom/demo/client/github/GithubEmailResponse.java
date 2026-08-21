package com.vengdom.demo.client.github;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * GitHub's /user/emails response - used to find a verified primary email
 * when the main /user profile's email field is null (private by default
 * unless the user opts to expose it).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GithubEmailResponse(
        String email,
        boolean primary,
        boolean verified,
        String visibility
) {
}
