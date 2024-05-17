package dev.bogdanjovanovic.jwtsecurity.auth.mfa.otp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import dev.bogdanjovanovic.jwtsecurity.exception.ApiResponse;
import dev.bogdanjovanovic.jwtsecurity.exception.ApiResponseWrapper;
import dev.bogdanjovanovic.jwtsecurity.user.User;
import dev.bogdanjovanovic.jwtsecurity.user.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
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
  private final ObjectMapper objectMapper;

  public OtpAuthFilter(final UserRepository userRepository) {
    this.userRepository = userRepository;
    this.objectMapper = new ObjectMapper();
    this.objectMapper.registerModule(new JavaTimeModule());
    this.objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
  }

  @Override
  protected void doFilterInternal(
      @NonNull final HttpServletRequest request,
      @NonNull final HttpServletResponse response,
      @NonNull final FilterChain filterChain) throws ServletException, IOException {
    final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (!request.getRequestURI().contains("mfa")) {
      filterChain.doFilter(request, response);
      return;
    }
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

  private void returnUnauthorized(@NonNull final HttpServletResponse response,
      final String path) throws IOException {
    final ApiResponse apiResponse = new ApiResponse(path, "Authentication failed",
        HttpServletResponse.SC_UNAUTHORIZED, LocalDateTime.now());
    final ApiResponseWrapper<ApiResponse> apiResponseWrapper = new ApiResponseWrapper<>(apiResponse);
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response.getWriter().write(objectMapper.writeValueAsString(apiResponseWrapper));
  }
}
