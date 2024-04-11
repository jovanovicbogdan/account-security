package dev.bogdanjovanovic.jwtsecurity.auth;

import dev.bogdanjovanovic.jwtsecurity.auth.User.Role;
import dev.bogdanjovanovic.jwtsecurity.exception.ConflictException;
import dev.bogdanjovanovic.jwtsecurity.exception.UnauthorizedException;
import dev.bogdanjovanovic.jwtsecurity.token.Token;
import dev.bogdanjovanovic.jwtsecurity.token.Token.TokenType;
import dev.bogdanjovanovic.jwtsecurity.token.TokenRepository;
import dev.bogdanjovanovic.jwtsecurity.token.TokenService;
import java.util.List;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

  private final TokenService tokenService;
  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final TokenRepository tokenRepository;
  private final AuthenticationManager authenticationManager;

  public AuthService(final TokenService tokenService, final UserRepository userRepository,
      final PasswordEncoder passwordEncoder, final TokenRepository tokenRepository,
      final AuthenticationManager authenticationManager) {
    this.tokenService = tokenService;
    this.userRepository = userRepository;
    this.passwordEncoder = passwordEncoder;
    this.tokenRepository = tokenRepository;
    this.authenticationManager = authenticationManager;
  }

  public void register(final RegisterRequest request) {
    userRepository.findByUsername(request.username()).ifPresent((user) -> {
      throw new ConflictException(
          "The username '" + user.getUsername() + "' is already registered.");
    });
    final User user = User.builder()
        .firstName(request.firstName())
        .lastName(request.lastName())
        .email(request.email())
        .username(request.username())
        .passwordHash(passwordEncoder.encode(request.password()))
        .role(Role.USER)
        .build();
    userRepository.save(user);
  }

  @Transactional(isolation = Isolation.SERIALIZABLE)
  public AuthUserResponse authenticate(final LoginRequest request) {
    final User user = userRepository.findByUsername(request.username())
        .orElseThrow(() -> new UnauthorizedException("Authentication failed"));
    authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
        request.username(), request.password()
    ));
    revokeAllUserTokens(user);
    final String authToken = tokenService.generateJwtToken(user, TokenType.AUTH);
    final String refreshToken = tokenService.generateJwtToken(user, TokenType.REFRESH);
    saveUserToken(user, refreshToken);
    return new AuthUserResponse(
        user.getUserId(), user.getFirstName(), user.getLastName(), user.getEmail(),
        user.getUsername(), user.getRole(), authToken, refreshToken
    );
  }

  @Transactional(isolation = Isolation.SERIALIZABLE)
  public AuthUserResponse refreshAuthToken(final String refreshToken) {
    final Token token = tokenRepository.findByToken(refreshToken)
        .orElseThrow(() -> new UnauthorizedException("Invalid refresh token"));
    if (token.isRevoked() || token.isExpired()) {
      throw new UnauthorizedException("Invalid refresh token");
    }
    final User user = token.getUser();
    userRepository.findByUsername(user.getUsername())
        .orElseThrow(() -> new UnauthorizedException("Invalid refresh token"));
    revokeAllUserTokens(user);
    final String authToken = tokenService.generateJwtToken(user, TokenType.AUTH);
    saveUserToken(user, refreshToken);
    return new AuthUserResponse(
        user.getUserId(), user.getFirstName(), user.getLastName(), user.getEmail(),
        user.getUsername(), user.getRole(), authToken, null
    );
  }

  private void revokeAllUserTokens(final User user) {
    final List<Token> validUserTokens = tokenRepository.findAllValidTokensByUserId(
        user.getUserId());
    if (validUserTokens.isEmpty()) {
      return;
    }

    validUserTokens.forEach(token -> {
      token.setRevoked(true);
      token.setExpired(true);
    });

    tokenRepository.saveAll(validUserTokens);
  }

  private void saveUserToken(final User user, final String jwtToken) {
    final Token token = new Token(
        jwtToken,
        false,
        false,
        user
    );
    tokenRepository.save(token);
  }
}
