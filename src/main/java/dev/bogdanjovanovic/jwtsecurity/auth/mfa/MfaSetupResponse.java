package dev.bogdanjovanovic.jwtsecurity.auth.mfa;

public record MfaSetupResponse(String qrImageBase64String, String secret) {
}
