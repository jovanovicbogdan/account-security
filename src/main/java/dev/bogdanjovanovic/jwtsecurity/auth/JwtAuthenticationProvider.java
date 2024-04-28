package dev.bogdanjovanovic.jwtsecurity.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.stereotype.Component;

@Component
public class JwtAuthenticationProvider implements AuthenticationProvider {

  private final Logger log = LoggerFactory.getLogger(JwtAuthenticationProvider.class);

  private final JwtDecoder jwtDecoder;
  private final JwtAuthenticationConverter jwtAuthenticationConverter;

  public JwtAuthenticationProvider(final JwtDecoder jwtDecoder,
      final JwtAuthenticationConverter jwtAuthenticationConverter) {
    this.jwtDecoder = jwtDecoder;
    this.jwtAuthenticationConverter = jwtAuthenticationConverter;
  }

  @Override
  public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
    final BearerTokenAuthenticationToken bearer = (BearerTokenAuthenticationToken) authentication;
    final Jwt jwt = getJwt(bearer);
    final AbstractAuthenticationToken token = jwtAuthenticationConverter.convert(jwt);
    if (token.getDetails() == null) {
      token.setDetails(bearer.getDetails());
    }
    return token;
  }

  @Override
  public boolean supports(final Class<?> authentication) {
    return BearerTokenAuthenticationToken.class.isAssignableFrom(authentication);
  }

  private Jwt getJwt(final BearerTokenAuthenticationToken bearer) {
    try {
      return jwtDecoder.decode(bearer.getToken());
    }
    catch (BadJwtException failed) {
      log.debug("Authentication failed. Invalid JWT.");
      throw new InvalidBearerTokenException(failed.getMessage(), failed);
    }
    catch (JwtException failed) {
      throw new AuthenticationServiceException(failed.getMessage(), failed);
    }
  }
}
