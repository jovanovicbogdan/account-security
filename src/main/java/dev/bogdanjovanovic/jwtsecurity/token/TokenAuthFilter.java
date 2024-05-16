package dev.bogdanjovanovic.jwtsecurity.token;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import dev.bogdanjovanovic.jwtsecurity.exception.ApiResponse;
import dev.bogdanjovanovic.jwtsecurity.exception.ApiResponseWrapper;
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
import org.springframework.web.filter.OncePerRequestFilter;

public class TokenAuthFilter extends OncePerRequestFilter {

  private static final Logger log = LoggerFactory.getLogger(TokenAuthFilter.class);

  private final ObjectMapper objectMapper;

  public TokenAuthFilter() {
    this.objectMapper = new ObjectMapper();
    this.objectMapper.registerModule(new JavaTimeModule());
    this.objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
  }

  @Override
  protected void doFilterInternal(
      @NonNull final HttpServletRequest request,
      @NonNull final HttpServletResponse response,
      @NonNull final FilterChain filterChain) throws ServletException, IOException {
    final String path = request.getRequestURI();

    if (path.contains("auth")) {
      filterChain.doFilter(request, response);
      return;
    }

    final String authHeader = request.getHeader("authorization");

    try {
      if (authHeader != null && authHeader.startsWith("Bearer ")) {
        filterChain.doFilter(request, response);
      } else {
        log.debug("Authentication failed. No token provided.");
        returnUnauthorized(response, path);
      }
    } catch (final Exception e) {
      log.debug(e.getMessage());
      returnUnauthorized(response, path);
    }
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
