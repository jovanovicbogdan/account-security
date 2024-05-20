package dev.bogdanjovanovic.accountsecurity.exception;

import java.time.LocalDateTime;

public record ApiResponse(String path, String message, int statusCode, LocalDateTime timestamp) {

}
