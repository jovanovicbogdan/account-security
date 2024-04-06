package dev.bogdanjovanovic.jwtsecurity.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import dev.bogdanjovanovic.jwtsecurity.auth.UserRepository;
import dev.bogdanjovanovic.jwtsecurity.exception.UnauthorizedException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

@Configuration
public class ApplicationConfig {

  private final RsaKeyProperties rsaKeyProperties;
  private final UserRepository userRepository;

  public ApplicationConfig(final RsaKeyProperties rsaKeyProperties,
      final UserRepository userRepository) {
    this.rsaKeyProperties = rsaKeyProperties;
    this.userRepository = userRepository;
  }

  @Bean
  public JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder.withPublicKey(rsaKeyProperties.rsaPublicKey()).build();
  }

  @Bean
  public JwtEncoder jwtEncoder() {
    final JWK jwk = new RSAKey.Builder(rsaKeyProperties.rsaPublicKey()).privateKey(
        rsaKeyProperties.rsaPrivateKey()).build();
    final JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
    return new NimbusJwtEncoder(jwks);
  }

  @Bean
  public UserDetailsService userDetailsService() {
    return username -> userRepository.findByUsername(username)
        .orElseThrow(() -> new UnauthorizedException("Authentication failed"));
  }

}
