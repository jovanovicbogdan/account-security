package dev.bogdanjovanovic.jwtsecurity.auth;

public record AuthUser(boolean requiresMfa, String authToken, String refreshToken) {
}
