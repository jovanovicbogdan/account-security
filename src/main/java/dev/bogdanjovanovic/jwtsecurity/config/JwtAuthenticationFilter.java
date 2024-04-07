package dev.bogdanjovanovic.jwtsecurity.config;

import dev.bogdanjovanovic.jwtsecurity.token.TokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private final TokenService tokenService;
  private final UserDetailsService userDetailsService;

  public JwtAuthenticationFilter(final TokenService tokenService,
      final UserDetailsService userDetailsService) {
    this.tokenService = tokenService;
    this.userDetailsService = userDetailsService;
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
    try {
      if (authenticateWithToken(token)) {
        filterChain.doFilter(request, response);
      } else {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      }
    } catch (Exception e) {
      response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }
  }

  private boolean authenticateWithToken(final String token) {
    final String username = tokenService.extractUsername(token);
    final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (username != null && authentication == null) {
      final UserDetails userDetails = userDetailsService.loadUserByUsername(username);
      return tokenService.isTokenValid(token, userDetails);
    }
    return false;
  }
}
