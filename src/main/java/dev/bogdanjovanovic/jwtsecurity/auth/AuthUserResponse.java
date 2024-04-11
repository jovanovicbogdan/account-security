package dev.bogdanjovanovic.jwtsecurity.auth;

import dev.bogdanjovanovic.jwtsecurity.auth.User.Role;
import java.util.UUID;

public record AuthUserResponse(UUID userId, String firstName, String lastName, String email,
                               String username, Role role, String authToken) {

}
