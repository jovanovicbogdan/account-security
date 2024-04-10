package dev.bogdanjovanovic.jwtsecurity.auth;

import dev.bogdanjovanovic.jwtsecurity.auth.User.Role;

public record AuthUserResponse(long userId, String firstName, String lastName, String email,
                               String username, Role role, String authToken) {

}
