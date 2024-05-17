package dev.bogdanjovanovic.jwtsecurity.auth;

import dev.bogdanjovanovic.jwtsecurity.token.TokenUtils;
import dev.bogdanjovanovic.jwtsecurity.user.User;
import dev.bogdanjovanovic.jwtsecurity.user.UserRepository;
import dev.bogdanjovanovic.jwtsecurity.exception.UnauthorizedException;
import dev.bogdanjovanovic.jwtsecurity.token.Token.TokenType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.stereotype.Component;

@Component
public class AuthTokenProvider implements AuthenticationProvider {

  private final Logger log = LoggerFactory.getLogger(AuthTokenProvider.class);

  private final JwtDecoder jwtDecoder;
  private final JwtAuthenticationConverter jwtAuthenticationConverter;
  private final TokenUtils tokenUtils;
  private final UserRepository userRepository;

  public AuthTokenProvider(final JwtDecoder jwtDecoder,
      final JwtAuthenticationConverter jwtAuthenticationConverter,
      final TokenUtils tokenUtils, final UserRepository userRepository) {
    this.jwtDecoder = jwtDecoder;
    this.jwtAuthenticationConverter = jwtAuthenticationConverter;
    this.tokenUtils = tokenUtils;
    this.userRepository = userRepository;
  }

  @Override
  public Authentication authenticate(final Authentication authentication)
      throws UnauthorizedException {
    final BearerTokenAuthenticationToken bearer = (BearerTokenAuthenticationToken) authentication;
    final Jwt jwt = getJwt(bearer);
    final String subjectClaim = jwt.getSubject();
    final User user = userRepository.findByUsername(subjectClaim)
        .orElseThrow(() -> new UnauthorizedException("Authentication failed"));
    final boolean isTokenValid = tokenUtils.isTokenValid(jwt.getTokenValue(), subjectClaim,
        TokenType.AUTH, user.getRole());
    if (!isTokenValid) {
      throw new UnauthorizedException("Authentication failed");
    }
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
    } catch (BadJwtException failed) {
      log.debug("Authentication failed. Invalid JWT.");
      throw new InvalidBearerTokenException(failed.getMessage(), failed);
    } catch (JwtException failed) {
      throw new AuthenticationServiceException(failed.getMessage(), failed);
    }
  }
}
