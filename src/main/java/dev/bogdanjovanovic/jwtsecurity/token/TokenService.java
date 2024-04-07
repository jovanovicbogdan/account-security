package dev.bogdanjovanovic.jwtsecurity.token;

import dev.bogdanjovanovic.jwtsecurity.auth.User;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
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
  private final TokenRepository tokenRepository;

  public TokenService(final JwtEncoder jwtEncoder, final JwtDecoder jwtDecoder,
      final TokenRepository tokenRepository) {
    this.jwtEncoder = jwtEncoder;
    this.jwtDecoder = jwtDecoder;
    this.tokenRepository = tokenRepository;
  }

  public String generateJwtToken(final User user) {
    final Instant now = Instant.now();
    final String scope = user.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .collect(Collectors.joining(" "));
    final JwtClaimsSet claims = JwtClaimsSet.builder()
        .issuer("self")
        .issuedAt(now)
        .expiresAt(now.plus(15L, ChronoUnit.MINUTES))
        .subject(user.getUsername())
        .claim("scope", scope)
        .build();
    return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
  }

  public String extractUsername(final String token) {
    final Jwt jwt = jwtDecoder.decode(token);
    return jwt.getSubject();
  }

  public Instant extractExpiration(final String token) {
    final Jwt jwt = jwtDecoder.decode(token);
    return jwt.getExpiresAt();
  }

  public boolean isTokenValid(final String token, final UserDetails userDetails) {
    final String username = extractUsername(token);
    return tokenRepository.findByToken(token)
        .map(t -> (username.equals(userDetails.getUsername())) && !isTokenExpired(token)
            && !t.isRevoked())
        .orElse(false);
  }

  public boolean isTokenExpired(final String token) {
    return extractExpiration(token).isBefore(Instant.now());
  }
}
