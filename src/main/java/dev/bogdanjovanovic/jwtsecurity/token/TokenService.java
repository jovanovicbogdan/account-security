package dev.bogdanjovanovic.jwtsecurity.token;

import dev.bogdanjovanovic.jwtsecurity.auth.User;
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
    // Subtract 60 seconds from the expiration time to account for default clock skew in JwtTimestampValidator
    final Instant now = Instant.now().minusSeconds(60L);
    Instant expiresAt = now.plus(tokenProperties.authTokenExpiration(), ChronoUnit.MILLIS);
    if (TokenType.REFRESH.equals(tokenType)) {
      expiresAt = now.plus(tokenProperties.refreshTokenExpiration(), ChronoUnit.MILLIS);
    }
    final String scope = user.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .collect(Collectors.joining(" "));
    final JwtClaimsSet claims = JwtClaimsSet.builder()
        .issuer("self")
        .issuedAt(now)
        .notBefore(now)
        .expiresAt(expiresAt)
        .subject(user.getUsername())
        .claim("scope", scope)
        .claim("type", tokenType.name())
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
    return TokenType.valueOf(jwt.getClaimAsString("type"));
  }

  public boolean isTokenValid(final String token, final String subject,
      final TokenType tokenType) {
    final String subjectClaim = extractSubject(token);
    final String tokenTypeClaim = extractTokenType(token).name();
    final boolean isExpired = Instant.now().isAfter(extractExpiration(token));
    return subjectClaim.equals(subject)
        && tokenTypeClaim.equals(tokenType.name())
        && isExpired;
  }

  public boolean isTokenExpired(final String token) {
    return extractExpiration(token).isBefore(Instant.now());
  }
}
