package dev.bogdanjovanovic.jwtsecurity.auth;

import java.util.UUID;

public record AuthResponse(UUID userId, String username, boolean requiresMfa, String authToken) {

}
