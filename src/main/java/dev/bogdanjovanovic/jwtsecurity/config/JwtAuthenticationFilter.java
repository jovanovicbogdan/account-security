package dev.bogdanjovanovic.jwtsecurity.config;

import dev.bogdanjovanovic.jwtsecurity.token.TokenService;
import dev.bogdanjovanovic.jwtsecurity.token.TokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private final TokenService tokenService;
  private final UserDetailsService userDetailsService;
  private final TokenRepository tokenRepository;

  public JwtAuthenticationFilter(final TokenService tokenService,
      final UserDetailsService userDetailsService, final TokenRepository tokenRepository) {
    this.tokenService = tokenService;
    this.userDetailsService = userDetailsService;
    this.tokenRepository = tokenRepository;
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
      if (authenticateWithToken(token, request)) {
        filterChain.doFilter(request, response);
      } else {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      }
    } catch (Exception e) {
      response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }
  }

  private boolean authenticateWithToken(final String token, final HttpServletRequest request) {
    final String username = tokenService.extractUsername(token);
    final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (username != null && authentication == null) {
      final UserDetails userDetails = userDetailsService.loadUserByUsername(username);
      final boolean isTokenValid = tokenRepository.findByToken(token)
          .map(t -> !t.isExpired() && !t.isRevoked() && tokenService.isTokenValid(token, userDetails))
          .orElse(false);
      if (isTokenValid) {
        final UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
            userDetails, null, userDetails.getAuthorities()
        );
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);
        return true;
      }
    }
    return false;
  }
}
