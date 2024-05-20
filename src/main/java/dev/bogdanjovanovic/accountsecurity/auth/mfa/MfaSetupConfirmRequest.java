package dev.bogdanjovanovic.accountsecurity.auth.mfa;

import jakarta.validation.constraints.NotBlank;

public record MfaSetupConfirmRequest(@NotBlank String code) {
}
