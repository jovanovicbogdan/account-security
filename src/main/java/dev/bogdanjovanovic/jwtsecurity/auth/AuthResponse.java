package dev.bogdanjovanovic.jwtsecurity.auth;

public record AuthResponse(boolean requiresMfa, String authToken) {

}
