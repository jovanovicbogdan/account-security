package dev.bogdanjovanovic.jwtsecurity.config;

import dev.bogdanjovanovic.jwtsecurity.auth.AuthTokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity(debug = true)
public class SecurityConfig {

  private static final String[] WHITE_LIST_URL = {
      "/api/v1/auth/register",
      "/api/v1/auth/login",
      "/api/v1/auth/logout",
      "/api/v1/auth/refresh"
  };
  private final AuthTokenProvider authTokenProvider;
//  private final TotpAuthFilter totpAuthFilter;

  public SecurityConfig(final AuthTokenProvider authTokenProvider) {
    this.authTokenProvider = authTokenProvider;
//    this.totpAuthFilter = totpAuthFilter;
  }

  @Bean
  public SecurityFilterChain securityFilterChain(final HttpSecurity http) throws Exception {
    return http
        .csrf(AbstractHttpConfigurer::disable)
        .authorizeHttpRequests(auth -> {
          auth.requestMatchers(WHITE_LIST_URL).permitAll();
          auth.anyRequest().authenticated();
        })
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
//        .addFilterAfter(totpAuthFilter, BearerTokenAuthenticationFilter.class)
        .authenticationProvider(authTokenProvider)
        .exceptionHandling(exceptions -> exceptions
            .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
            .accessDeniedHandler(new BearerTokenAccessDeniedHandler()))
        .build();
  }

}
