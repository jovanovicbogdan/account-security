package dev.bogdanjovanovic.jwtsecurity.auth;

import dev.bogdanjovanovic.jwtsecurity.exception.BadRequestException;
import dev.bogdanjovanovic.jwtsecurity.token.Token;
import dev.bogdanjovanovic.jwtsecurity.token.TokenRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Arrays;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class LogoutService implements LogoutHandler {

  private final TokenRepository tokenRepository;

  public LogoutService(final TokenRepository tokenRepository) {
    this.tokenRepository = tokenRepository;
  }

  @Transactional
  @Override
  public void logout(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final Authentication authentication) {
    final Cookie refreshTokenCookie = Arrays.stream(request.getCookies())
        .filter(cookie -> cookie.getName().equals("refresh-token"))
        .findFirst()
        .orElseThrow(() -> new BadRequestException("Invalid refresh token"));
    final Token storedToken = tokenRepository.findByToken(refreshTokenCookie.getValue())
        .orElse(null);
    if (storedToken != null) {
      storedToken.setExpired(true);
      storedToken.setRevoked(true);
      tokenRepository.save(storedToken);
      SecurityContextHolder.clearContext();
      final Cookie cookie = new Cookie("refresh-token", "");
      cookie.setHttpOnly(true);
      cookie.setMaxAge(0);
      response.addCookie(cookie);
    }
  }
}
