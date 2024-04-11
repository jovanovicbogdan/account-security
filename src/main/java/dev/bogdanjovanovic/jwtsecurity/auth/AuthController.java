package dev.bogdanjovanovic.jwtsecurity.auth;

import dev.bogdanjovanovic.jwtsecurity.exception.ApiResponseWrapper;
import dev.bogdanjovanovic.jwtsecurity.exception.UnauthorizedException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import javax.swing.text.html.Option;
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
  }

  @PostMapping("login")
  public ApiResponseWrapper<Object> login(
      @RequestBody @Valid final LoginRequest request, final HttpServletResponse response) {
    log.info("Received login request for user: {}", request.username());
    final AuthUser authUser = authService.authenticate(request);
    final Cookie cookie = new Cookie("refresh-token", authUser.refreshToken());
    cookie.setHttpOnly(true);
//    cookie.setSecure(true);
    response.addCookie(cookie);
    return new ApiResponseWrapper<>(
        new AuthUserResponse(authUser.userId(), authUser.firstName(), authUser.lastName(),
            authUser.email(), authUser.username(), authUser.role(), authUser.authToken())
    );
  }

  @PostMapping("refresh-token")
  public ApiResponseWrapper<AuthUserResponse> refreshToken(final HttpServletRequest request) {
    final Cookie refreshTokenCookie = Arrays.stream(request.getCookies())
        .filter(cookie -> cookie.getName().equals("refresh-token"))
        .findFirst()
        .orElseThrow(() -> new UnauthorizedException("Authentication failed"));
    final AuthUser authUser = authService.refreshAuthToken(refreshTokenCookie.getValue());
    return new ApiResponseWrapper<>(
        new AuthUserResponse(authUser.userId(), authUser.firstName(), authUser.lastName(),
            authUser.email(), authUser.username(), authUser.role(), authUser.authToken())
    );
  }

}
