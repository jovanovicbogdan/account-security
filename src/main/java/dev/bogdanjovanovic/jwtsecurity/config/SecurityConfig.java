package dev.bogdanjovanovic.jwtsecurity.config;

import dev.bogdanjovanovic.jwtsecurity.mfa.totp.TotpAuthFilter;
import dev.bogdanjovanovic.jwtsecurity.token.TokenAuthProvider;
import dev.bogdanjovanovic.jwtsecurity.token.TokenAuthFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  private static final String[] WHITE_LIST_URL = {
      "/api/v1/auth/**"
  };
  private final TokenAuthFilter tokenAuthFilter;
  private final TotpAuthFilter totpAuthFilter;
  private final TokenAuthProvider tokenAuthProvider;

  public SecurityConfig(final TokenAuthFilter tokenAuthFilter, final TotpAuthFilter totpAuthFilter,
      final TokenAuthProvider tokenAuthProvider) {
    this.tokenAuthFilter = tokenAuthFilter;
    this.totpAuthFilter = totpAuthFilter;
    this.tokenAuthProvider = tokenAuthProvider;
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
        .addFilterBefore(tokenAuthFilter, BearerTokenAuthenticationFilter.class)
        .addFilterAfter(totpAuthFilter, UsernamePasswordAuthenticationFilter.class)
        .authenticationProvider(tokenAuthProvider)
//        .exceptionHandling(Customizer.withDefaults())
//        .logout((logout) -> logout.logoutUrl("/api/v1/auth/logout")
//            .addLogoutHandler(logoutHandler)
//            .logoutSuccessHandler(
//                ((request, response, authentication) -> SecurityContextHolder.clearContext())))
        .exceptionHandling(exceptions -> exceptions
            .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
            .accessDeniedHandler(new BearerTokenAccessDeniedHandler()))
        .build();
  }

}
