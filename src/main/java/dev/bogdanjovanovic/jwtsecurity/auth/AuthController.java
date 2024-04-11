package dev.bogdanjovanovic.jwtsecurity.auth;

import dev.bogdanjovanovic.jwtsecurity.exception.ApiResponseWrapper;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@CrossOrigin(origins = {"http://localhost:4200"})
public class AuthController {

  private static final Logger log = LoggerFactory.getLogger(AuthController.class);

  private final AuthService authService;

  public AuthController(final AuthService authService) {
    this.authService = authService;
  }

  @PostMapping("register")
  @ResponseStatus(HttpStatus.CREATED)
  public void register(@RequestBody @Valid final RegisterRequest request) {
    authService.register(request);
//    Cookie cookie = new Cookie("refresh-token", "kirYksalekPgkslkAsnk");
//    cookie.setHttpOnly(true);
//    cookie.setSecure(true);
  }

  @PostMapping("login")
  public ApiResponseWrapper<AuthUserResponse> login(
      @RequestBody @Valid final LoginRequest request) {
    log.info("Received login request for user: {}", request.username());
    return new ApiResponseWrapper<>(authService.authenticate(request));
  }

  @PostMapping("refresh-token")
  public ApiResponseWrapper<AuthUserResponse> refreshToken(
      @RequestBody @Valid final RefreshToken request) {
    return new ApiResponseWrapper<>(authService.refreshAuthToken(request.refreshToken()));
  }

  public record RefreshToken(@NotBlank String refreshToken) {

  }

}
