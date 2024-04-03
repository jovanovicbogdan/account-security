package dev.bogdanjovanovic.jwtsecurity.auth;

import dev.bogdanjovanovic.jwtsecurity.exception.ApiResponseWrapper;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Validated
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

  private static final Logger log = LoggerFactory.getLogger(AuthController.class);

  private final AuthService authService;

  public AuthController(final AuthService authService) {
    this.authService = authService;
  }

  @PostMapping("login")
  public ApiResponseWrapper<AuthResponse> login(@Valid @RequestBody final AuthRequest request) {
    final AuthResponse authenticate = authService.authenticate(request);
    return new ApiResponseWrapper<>(authenticate);
  }

  @PostMapping("register")
  public void register(@Valid @RequestBody final RegisterRequest request) {
    authService.register(request);
  }

}
