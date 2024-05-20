package dev.bogdanjovanovic.accountsecurity.auth;

import jakarta.validation.constraints.NotBlank;

public record RegisterRequest(
    @NotBlank String firstName,
    @NotBlank String lastName,
    @NotBlank String email,
    @NotBlank String username,
    @NotBlank String password,
    @NotBlank boolean requiresMfa
) {

}
