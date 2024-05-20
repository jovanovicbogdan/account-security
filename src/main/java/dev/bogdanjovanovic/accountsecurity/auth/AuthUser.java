package dev.bogdanjovanovic.accountsecurity.auth;

public record AuthUser(boolean requiresMfa, String authToken, String refreshToken) {
}
