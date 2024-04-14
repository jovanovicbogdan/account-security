package dev.bogdanjovanovic.jwtsecurity.exception;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.resource.NoResourceFoundException;

@ControllerAdvice
public class GlobalExceptionHandler {

  private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<ApiResponseWrapper<ApiResponse>> handleException(
      final MethodArgumentNotValidException ex,
      final HttpServletRequest request) {
    final List<String> errors = ex.getBindingResult().getFieldErrors().stream()
        .map(error -> error.getField() + ": " + error.getDefaultMessage())
        .collect(Collectors.toList());

    final String errorMessage = String.join(", ", errors);
    final ApiResponse response = new ApiResponse(request.getRequestURI(),
        errorMessage, HttpStatus.BAD_REQUEST.value(),
        LocalDateTime.now());
    ex.printStackTrace();
    return new ResponseEntity<>(new ApiResponseWrapper<>(response), HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(ConstraintViolationException.class)
  public ResponseEntity<ApiResponseWrapper<ApiResponse>> handleException(
      final ConstraintViolationException ex,
      final HttpServletRequest request) {
    final ApiResponse response = new ApiResponse(request.getRequestURI(),
        "Invalid parameter(s)", HttpStatus.BAD_REQUEST.value(),
        LocalDateTime.now());
    return new ResponseEntity<>(new ApiResponseWrapper<>(response), HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(NoResourceFoundException.class)
  public ResponseEntity<ApiResponseWrapper<ApiResponse>> handleException(
      final NoResourceFoundException ex,
      final HttpServletRequest request) {
    final ApiResponse response = new ApiResponse(request.getRequestURI(),
        ex.getMessage(), HttpStatus.NOT_FOUND.value(),
        LocalDateTime.now());
    return new ResponseEntity<>(new ApiResponseWrapper<>(response), HttpStatus.NOT_FOUND);
  }

  @ExceptionHandler(ConflictException.class)
  public ResponseEntity<ApiResponseWrapper<ApiResponse>> handleException(
      final ConflictException ex,
      final HttpServletRequest request) {
    final ApiResponse response = new ApiResponse(request.getRequestURI(),
        ex.getMessage(), HttpStatus.CONFLICT.value(),
        LocalDateTime.now());
    return new ResponseEntity<>(new ApiResponseWrapper<>(response), HttpStatus.CONFLICT);
  }

  @ExceptionHandler(UnauthorizedException.class)
  public ResponseEntity<ApiResponseWrapper<ApiResponse>> handleException(
      final UnauthorizedException ex,
      final HttpServletRequest request) {
    log.info("Unauthorized access attempted: {}", ex.getMessage());
    final ApiResponse response = new ApiResponse(request.getRequestURI(),
        ex.getMessage(), HttpStatus.UNAUTHORIZED.value(),
        LocalDateTime.now());
    return new ResponseEntity<>(new ApiResponseWrapper<>(response), HttpStatus.UNAUTHORIZED);
  }

  @ExceptionHandler(JwtValidationException.class)
  public ResponseEntity<ApiResponseWrapper<ApiResponse>> handleException(
      final JwtValidationException ex,
      final HttpServletRequest request) {
    log.info(ex.getMessage());
    final ApiResponse response = new ApiResponse(request.getRequestURI(),
        ex.getMessage(), HttpStatus.UNAUTHORIZED.value(),
        LocalDateTime.now());
    return new ResponseEntity<>(new ApiResponseWrapper<>(response), HttpStatus.UNAUTHORIZED);
  }

  @ExceptionHandler(BadCredentialsException.class)
  public ResponseEntity<ApiResponseWrapper<ApiResponse>> handleException(
      final BadCredentialsException ex,
      final HttpServletRequest request) {
    log.info("Bad credentials: {}", ex.getMessage());
    final ApiResponse response = new ApiResponse(request.getRequestURI(),
        "Authentication failed", HttpStatus.UNAUTHORIZED.value(),
        LocalDateTime.now());
    return new ResponseEntity<>(new ApiResponseWrapper<>(response), HttpStatus.UNAUTHORIZED);
  }

  @ExceptionHandler(Exception.class)
  public ResponseEntity<ApiResponseWrapper<ApiResponse>> handleException(final Exception ex,
      final HttpServletRequest request) {
    final ApiResponse response = new ApiResponse(request.getRequestURI(), null,
        HttpStatus.INTERNAL_SERVER_ERROR.value(), LocalDateTime.now());
    ex.printStackTrace();
    return new ResponseEntity<>(new ApiResponseWrapper<>(response),
        HttpStatus.INTERNAL_SERVER_ERROR);
  }

}
