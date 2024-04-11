package dev.bogdanjovanovic.jwtsecurity.auth;

import jakarta.validation.constraints.NotBlank;

public record RefreshTokenRequest(@NotBlank String refreshToken) {

}
