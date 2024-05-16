package dev.bogdanjovanovic.jwtsecurity.mfa.totp;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

public class TotpAuthFilter extends OncePerRequestFilter {

  private static final Logger log = LoggerFactory.getLogger(TotpAuthFilter.class);

  @Override
  protected void doFilterInternal(
      @NonNull final HttpServletRequest request,
      @NonNull final HttpServletResponse response,
      @NonNull final FilterChain filterChain) throws ServletException, IOException {
    final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication != null) {
      // Proceed if authentication is not null
      if (authentication.isAuthenticated()) {
        final String username = authentication.getName();
        // Additional check if the user is authenticated
        log.info(String.format("TOTP FILTER %s authenticated", authentication.getName()));
        // Perform check of TOTP header
      }
      filterChain.doFilter(request, response);
    } else {
      log.warn("Authentication is null in TOTP filter.");
      // Handle case where authentication is null, possibly rethrowing as an error or redirecting
      filterChain.doFilter(request, response);
    }
  }
}
