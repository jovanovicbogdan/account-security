package dev.bogdanjovanovic.accountsecurity.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import dev.bogdanjovanovic.accountsecurity.exception.UnauthorizedException;
import dev.bogdanjovanovic.accountsecurity.user.UserRepository;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

@Configuration
public class ApplicationConfig {

  private final RsaKeyProperties rsaKeyProperties;
  private final UserRepository userRepository;

  public ApplicationConfig(final RsaKeyProperties rsaKeyProperties,
      final UserRepository userRepository) {
    this.rsaKeyProperties = rsaKeyProperties;
    this.userRepository = userRepository;
  }

  public JwtTimestampValidator jwtTimestampValidator() {
    return new JwtTimestampValidator(Duration.of(0L, ChronoUnit.SECONDS));
  }

  @Bean
  public JwtDecoder jwtDecoder() {
    final DelegatingOAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(
        Collections.singletonList(jwtTimestampValidator()));
    final NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder
        .withPublicKey(rsaKeyProperties.rsaPublicKey())
        .build();
    jwtDecoder.setJwtValidator(validator);
    return jwtDecoder;
  }

  @Bean
  public JwtEncoder jwtEncoder() {
    final JWK jwk = new RSAKey.Builder(rsaKeyProperties.rsaPublicKey()).privateKey(
        rsaKeyProperties.rsaPrivateKey()).build();
    final JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
    return new NimbusJwtEncoder(jwks);
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public UserDetailsService userDetailsService() {
    return username -> userRepository.findByUsername(username)
        .orElseThrow(() -> new UnauthorizedException("Authentication failed"));
  }

  @Bean
  public AuthenticationManager authenticationManager(
      final UserDetailsService userDetailsService,
      final PasswordEncoder passwordEncoder) {
    final DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
    authenticationProvider.setUserDetailsService(userDetailsService);
    authenticationProvider.setPasswordEncoder(passwordEncoder);

    return new ProviderManager(authenticationProvider);
  }

  @Bean
  public JwtAuthenticationConverter jwtAuthenticationConverter() {
    return new JwtAuthenticationConverter();
  }

}
