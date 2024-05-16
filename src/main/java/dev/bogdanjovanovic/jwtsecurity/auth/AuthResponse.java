package dev.bogdanjovanovic.jwtsecurity.auth;

import dev.bogdanjovanovic.jwtsecurity.user.User.Role;
import java.util.UUID;

public record AuthResponse(UUID userId, String firstName, String lastName, String email,
                           String username, Role role, boolean requiresMfa, String authToken) {

}