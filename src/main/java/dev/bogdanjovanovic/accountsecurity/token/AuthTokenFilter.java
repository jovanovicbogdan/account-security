package dev.bogdanjovanovic.accountsecurity.token;

import dev.bogdanjovanovic.accountsecurity.token.Token.TokenType;
import dev.bogdanjovanovic.accountsecurity.user.User;
import dev.bogdanjovanovic.accountsecurity.user.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class AuthTokenFilter extends OncePerRequestFilter {

  private final static Logger log = LoggerFactory.getLogger(AuthTokenFilter.class);
  private final UserRepository userRepository;
  private final TokenUtils tokenUtils;

  public AuthTokenFilter(final UserRepository userRepository, final TokenUtils tokenUtils) {
    this.userRepository = userRepository;
    this.tokenUtils = tokenUtils;
  }

  @Override
  protected void doFilterInternal(
      @NonNull final HttpServletRequest request,
      @NonNull final HttpServletResponse response,
      @NonNull final FilterChain filterChain) throws ServletException, IOException {
    final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication != null) {
      if (authentication instanceof JwtAuthenticationToken jwtAuthToken) {
        final Jwt jwt = jwtAuthToken.getToken();
        final String subjectClaim = jwt.getSubject();

        final Optional<User> optionalUser = userRepository.findByUsername(subjectClaim);
        if (optionalUser.isEmpty()) {
          response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
          return;
        }

        final User user = optionalUser.get();
        boolean isTokenValid;
        if (request.getRequestURI().contains("/auth/mfa/verify")) {
          isTokenValid = tokenUtils.isTokenValid(jwt.getTokenValue(), subjectClaim,
              TokenType.PRE_AUTH, user.getRole());
        } else {
          isTokenValid = tokenUtils.isTokenValid(jwt.getTokenValue(), subjectClaim,
              TokenType.AUTH, user.getRole());
        }

        if (!isTokenValid) {
          log.debug("Token is invalid for subject '{}'", subjectClaim);
          response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
          return;
        }
      }
    } else {
      log.debug("Authentication is null or not authenticated in AuthTokenFilter");
    }
    filterChain.doFilter(request, response);
  }
}
