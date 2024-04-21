package dev.bogdanjovanovic.jwtsecurity.user;

import dev.bogdanjovanovic.jwtsecurity.auth.User.Role;
import java.time.Instant;
import java.util.UUID;

public record UserResponse(UUID userId, String firstName, String lastName, String email,
                           String username, Role role, Instant createdAt, Instant updatedAt) {

}
