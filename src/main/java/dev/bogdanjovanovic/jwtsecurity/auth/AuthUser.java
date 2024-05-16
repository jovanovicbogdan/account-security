package dev.bogdanjovanovic.jwtsecurity.auth;

import java.util.UUID;

public record AuthUser(UUID userId, String username, boolean requiresMfa, String authToken,
                       String refreshToken) {

}
