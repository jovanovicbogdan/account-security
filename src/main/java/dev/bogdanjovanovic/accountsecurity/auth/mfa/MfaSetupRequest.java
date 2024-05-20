package dev.bogdanjovanovic.accountsecurity.auth.mfa;

import jakarta.validation.constraints.NotBlank;

public record MfaSetupRequest(@NotBlank String deviceName) {
}
