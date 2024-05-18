package dev.bogdanjovanovic.jwtsecurity.auth.mfa;

import jakarta.validation.constraints.NotBlank;

public record MfaSetupRequest(@NotBlank String deviceName) {
}
