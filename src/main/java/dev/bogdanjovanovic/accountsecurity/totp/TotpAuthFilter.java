package dev.bogdanjovanovic.accountsecurity.totp;

import dev.bogdanjovanovic.accountsecurity.user.User;
import dev.bogdanjovanovic.accountsecurity.user.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class TotpAuthFilter extends OncePerRequestFilter {

  private static final Logger log = LoggerFactory.getLogger(TotpAuthFilter.class);
  private final UserRepository userRepository;
  private final AuthenticationManager authenticationManager;

  public TotpAuthFilter(final UserRepository userRepository,
      final AuthenticationManager authenticationManager) {
    this.userRepository = userRepository;
    this.authenticationManager = authenticationManager;
  }

  @Override
  protected void doFilterInternal(
      @NonNull final HttpServletRequest request,
      @NonNull final HttpServletResponse response,
      @NonNull final FilterChain filterChain) throws ServletException, IOException {
    final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (!request.getRequestURI().contains("/auth/mfa/verify")) {
      filterChain.doFilter(request, response);
      return;
    }
    if (authentication != null) {
      if (authentication.isAuthenticated()) {
        final User user = userRepository.findByUsername(authentication.getName())
            .orElseThrow(() -> new UsernameNotFoundException("Authentication failed"));
        if (user.requiresMfa()) {
          final TotpConverter totpConverter = new TotpConverter(authentication);
          final Totp totp = totpConverter.convert(request);
          if (totp == null || totp.getCredentials().isBlank()) {
            log.info("TOTP code is missing for user '{}'", user.getUsername());
            response.setHeader("WWW-Authenticate", Totp.TOTP_HEADER_NAME);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
          }
          try {
            final Authentication authed = authenticationManager.authenticate(totp);
            SecurityContextHolder.getContext().setAuthentication(authed);
          } catch (AuthenticationException e) {
            response.setHeader("WWW-Authenticate", Totp.TOTP_HEADER_NAME);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
          }
        }
      }
      filterChain.doFilter(request, response);
    } else {
      log.info("Authentication is null in TOTP filter.");
      response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }
    filterChain.doFilter(request, response);
  }
}
