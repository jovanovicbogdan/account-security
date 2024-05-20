package dev.bogdanjovanovic.accountsecurity.auth.mfa;

public record MfaSetupResponse(String qrImageBase64String, String secret) {
}
