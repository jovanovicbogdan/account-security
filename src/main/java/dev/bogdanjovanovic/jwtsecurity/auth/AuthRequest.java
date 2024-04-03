package dev.bogdanjovanovic.jwtsecurity.auth;

import jakarta.validation.constraints.NotBlank;

public record AuthRequest(@NotBlank String username, @NotBlank String password) {

}
