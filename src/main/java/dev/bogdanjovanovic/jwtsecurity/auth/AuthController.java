package dev.bogdanjovanovic.jwtsecurity.auth;

import dev.bogdanjovanovic.jwtsecurity.exception.ApiResponseWrapper;
import dev.bogdanjovanovic.jwtsecurity.exception.BadRequestException;
import dev.bogdanjovanovic.jwtsecurity.exception.UnauthorizedException;
import dev.bogdanjovanovic.jwtsecurity.token.Token;
import dev.bogdanjovanovic.jwtsecurity.token.TokenRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@CrossOrigin(origins = {"http://localhost:4200"}, allowCredentials = "true")
public class AuthController {

  private static final Logger log = LoggerFactory.getLogger(AuthController.class);

  public static final String REFRESH_TOKEN_COOKIE_NAME = "asrt";

  @Value("${security.refresh-token-expiration}")
  private long refreshTokenExpiration;

  private final AuthService authService;
  private final TokenRepository tokenRepository;

  public AuthController(final AuthService authService, final TokenRepository tokenRepository) {
    this.authService = authService;
    this.tokenRepository = tokenRepository;
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
    final Cookie cookie = new Cookie(REFRESH_TOKEN_COOKIE_NAME, authUser.refreshToken());
    cookie.setHttpOnly(true);
    cookie.setPath("/");
    cookie.setMaxAge((int) (refreshTokenExpiration / 1000));
    cookie.setAttribute("SameSite", "Strict");
//    cookie.setSecure(true);
    response.addCookie(cookie);
    return new ApiResponseWrapper<>(
        new AuthUserResponse(authUser.userId(), authUser.firstName(), authUser.lastName(),
            authUser.email(), authUser.username(), authUser.role(), authUser.authToken())
    );
  }

  @PostMapping("refresh")
  public ApiResponseWrapper<AuthUserResponse> refreshToken(final HttpServletRequest request) {
    if (request.getCookies() == null || request.getCookies().length == 0) {
      throw new UnauthorizedException("Authentication failed");
    }
    final Cookie refreshTokenCookie = Arrays.stream(request.getCookies())
        .filter(cookie -> REFRESH_TOKEN_COOKIE_NAME.equals(cookie.getName()))
        .findFirst()
        .orElseThrow(() -> new UnauthorizedException("Authentication failed"));
    final AuthUser authUser = authService.refreshAuthToken(refreshTokenCookie.getValue());
    return new ApiResponseWrapper<>(
        new AuthUserResponse(authUser.userId(), authUser.firstName(), authUser.lastName(),
            authUser.email(), authUser.username(), authUser.role(), authUser.authToken())
    );
  }

  @Transactional
  @PostMapping("logout")
  public void logout(
      final HttpServletRequest request,
      final HttpServletResponse response) {
    if (request.getCookies() == null || request.getCookies().length == 0) {
      throw new UnauthorizedException("Logout failed");
    }
    final Cookie refreshTokenCookie = Arrays.stream(request.getCookies())
        .filter(cookie -> cookie.getName().equals(AuthController.REFRESH_TOKEN_COOKIE_NAME))
        .findFirst()
        .orElseThrow(() -> new BadRequestException("Invalid refresh token"));
    final Token storedToken = tokenRepository.findByToken(refreshTokenCookie.getValue())
        .orElse(null);
    if (storedToken != null) {
      storedToken.setExpired(true);
      storedToken.setRevoked(true);
      tokenRepository.save(storedToken);
//      final Cookie cookie = new Cookie(AuthController.REFRESH_TOKEN_COOKIE_NAME, "");
      refreshTokenCookie.setHttpOnly(true);
      refreshTokenCookie.setPath("/");
      refreshTokenCookie.setMaxAge(0);
      refreshTokenCookie.setAttribute("SameSite", "Strict");
      response.addCookie(refreshTokenCookie);
      SecurityContextHolder.clearContext();
    }
  }

}
