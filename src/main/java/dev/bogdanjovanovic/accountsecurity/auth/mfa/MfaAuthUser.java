package dev.bogdanjovanovic.accountsecurity.auth.mfa;

public record MfaAuthUser(String authToken, String refreshToken) {
}
