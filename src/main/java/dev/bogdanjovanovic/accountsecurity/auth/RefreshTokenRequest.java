package dev.bogdanjovanovic.accountsecurity.auth;

import jakarta.validation.constraints.NotBlank;

public record RefreshTokenRequest(@NotBlank String refreshToken) {

}
