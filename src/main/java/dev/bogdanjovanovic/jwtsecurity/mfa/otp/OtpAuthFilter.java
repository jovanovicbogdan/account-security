package dev.bogdanjovanovic.jwtsecurity.mfa.otp;

import dev.bogdanjovanovic.jwtsecurity.user.User;
import dev.bogdanjovanovic.jwtsecurity.user.UserRepository;
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
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class OtpAuthFilter extends OncePerRequestFilter {

  private static final Logger log = LoggerFactory.getLogger(OtpAuthFilter.class);
  private final UserRepository userRepository;

  public OtpAuthFilter(final UserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @Override
  protected void doFilterInternal(
      @NonNull final HttpServletRequest request,
      @NonNull final HttpServletResponse response,
      @NonNull final FilterChain filterChain) throws ServletException, IOException {
    final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication != null) {
      if (authentication.isAuthenticated()) {
        final JwtAuthenticationToken jwtAuthToken = (JwtAuthenticationToken) authentication;
        final Jwt jwt = jwtAuthToken.getToken();
        final User user = userRepository.findByUsername(jwt.getSubject())
            .orElseThrow(() -> new UsernameNotFoundException("Authentication failed"));
        if (user.requiresMfa()) {
          final Otp otp = new OtpConverter(authentication).convert(request);
          if (otp == null || otp.getCredentials().isBlank()) {
            log.info(String.format("OTP code is missing for user %s", user.getUsername()));
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setHeader("WWW-Authenticate", "OTP");
            return;
          }
          final String code = otp.getCredentials();
        }
      }
      filterChain.doFilter(request, response);
    } else {
      log.info("Authentication is null in OTP filter.");
    }
    filterChain.doFilter(request, response);
  }
}
