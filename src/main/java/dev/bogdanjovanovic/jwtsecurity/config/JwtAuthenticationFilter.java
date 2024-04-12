package dev.bogdanjovanovic.jwtsecurity.config;

import dev.bogdanjovanovic.jwtsecurity.token.Token.TokenType;
import dev.bogdanjovanovic.jwtsecurity.token.TokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private final TokenService tokenService;

  public JwtAuthenticationFilter(final TokenService tokenService) {
    this.tokenService = tokenService;
  }

  @Override
  protected void doFilterInternal(
      @NonNull final HttpServletRequest request,
      @NonNull final HttpServletResponse response,
      @NonNull final FilterChain filterChain) throws ServletException, IOException {
    final String authHeader = request.getHeader("Authorization");
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      filterChain.doFilter(request, response);
      return;
    }
    final String token = authHeader.substring(7);
    final TokenType tokenType = tokenService.extractTokenType(token);
    if (TokenType.AUTH.equals(tokenType)) {
      filterChain.doFilter(request, response);
    } else {
      response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//    try {
//      if (authenticateWithToken(token)) {
//        filterChain.doFilter(request, response);
//      } else {
//        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//      }
//    } catch (Exception e) {
//      response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//    }
  }

//  private boolean authenticateWithToken(final String token) {
//    final String subject = tokenService.extractSubject(token);
//    final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//    if (subject != null && authentication == null) {
//      final UserDetails userDetails = userDetailsService.loadUserByUsername(subject);
//      return tokenService.isTokenValid(token, userDetails);
//    }
//    return false;
//  }
}
