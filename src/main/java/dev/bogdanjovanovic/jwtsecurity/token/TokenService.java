package dev.bogdanjovanovic.jwtsecurity.token;

import dev.bogdanjovanovic.jwtsecurity.user.User;
import dev.bogdanjovanovic.jwtsecurity.user.User.Role;
import dev.bogdanjovanovic.jwtsecurity.token.Token.TokenType;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

@Service
public class TokenService {

  private final JwtEncoder jwtEncoder;
  private final JwtDecoder jwtDecoder;
  private final TokenProperties tokenProperties;

  public TokenService(final JwtEncoder jwtEncoder, final JwtDecoder jwtDecoder,
      final TokenProperties tokenProperties) {
    this.jwtEncoder = jwtEncoder;
    this.jwtDecoder = jwtDecoder;
    this.tokenProperties = tokenProperties;
  }

  public String generateJwtToken(final User user, final TokenType tokenType) {
    final Instant now = Instant.now();
    final Instant expiresAt = getExpirationByTokenType(tokenType);
    final String scope = user.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .collect(Collectors.joining(" "));
    final JwtClaimsSet claims = JwtClaimsSet.builder()
        .issuer("self")
        .issuedAt(now)
        .expiresAt(expiresAt)
        .subject(user.getUsername())
        .claim("scope", scope)
        .claim(ClaimNames.TYPE, tokenType.name())
        .claim(ClaimNames.ROLE, user.getRole().name())
        .build();
    return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
  }

  public String extractSubject(final String token) {
    final Jwt jwt = jwtDecoder.decode(token);
    return jwt.getSubject();
  }

  public Instant extractExpiration(final String token) {
    final Jwt jwt = jwtDecoder.decode(token);
    return jwt.getExpiresAt();
  }

  public TokenType extractTokenType(final String token) {
    final Jwt jwt = jwtDecoder.decode(token);
    return TokenType.valueOf(jwt.getClaimAsString(ClaimNames.TYPE));
  }

  public Role extractRole(final String token) {
    final Jwt jwt = jwtDecoder.decode(token);
    return Role.valueOf(jwt.getClaimAsString(ClaimNames.ROLE));
  }

  public boolean isTokenValid(final String token, final String subject,
      final TokenType tokenType, final Role role) {
    final String subjectClaim = extractSubject(token);
    final String tokenTypeClaim = extractTokenType(token).name();
    final Role roleClaim = extractRole(token);
    return subjectClaim.equals(subject)
        && tokenTypeClaim.equals(tokenType.name())
        && !isTokenExpired(token)
        && roleClaim.equals(role);
  }

  private boolean isTokenExpired(final String token) {
    return extractExpiration(token).isBefore(Instant.now());
  }

  private Instant getExpirationByTokenType(final TokenType tokenType) {
    Instant now = Instant.now();
    Instant expiresAt = null;
    if (TokenType.AUTH.equals(tokenType)) {
      expiresAt = now.plus(tokenProperties.authTokenExpiration(), ChronoUnit.MILLIS);
    }
    if (TokenType.REFRESH.equals(tokenType)) {
      expiresAt = now.plus(tokenProperties.refreshTokenExpiration(), ChronoUnit.MILLIS);
    }
    if (TokenType.PRE_AUTH.equals(tokenType)) {
      expiresAt = now.plus(tokenProperties.preAuthTokenExpiration(), ChronoUnit.MILLIS);
    }
    return expiresAt;
  }
}
