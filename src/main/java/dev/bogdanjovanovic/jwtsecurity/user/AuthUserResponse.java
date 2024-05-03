package dev.bogdanjovanovic.jwtsecurity.user;

import dev.bogdanjovanovic.jwtsecurity.user.User.Role;
import java.util.UUID;

public record AuthUserResponse(UUID userId, String firstName, String lastName, String email,
                               String username, Role role, String authToken) {

}
