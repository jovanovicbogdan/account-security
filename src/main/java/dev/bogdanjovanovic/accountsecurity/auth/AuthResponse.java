package dev.bogdanjovanovic.accountsecurity.auth;

public record AuthResponse(boolean requiresMfa, String authToken) {

}
