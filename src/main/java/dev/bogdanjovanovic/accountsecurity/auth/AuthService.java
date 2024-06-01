package dev.bogdanjovanovic.accountsecurity.auth;

import dev.bogdanjovanovic.accountsecurity.exception.ConflictException;
import dev.bogdanjovanovic.accountsecurity.totp.TotpDevice;
import dev.bogdanjovanovic.accountsecurity.user.User;
import dev.bogdanjovanovic.accountsecurity.user.User.Role;
import dev.bogdanjovanovic.accountsecurity.exception.UnauthorizedException;
import dev.bogdanjovanovic.accountsecurity.token.Token;
import dev.bogdanjovanovic.accountsecurity.token.Token.TokenType;
import dev.bogdanjovanovic.accountsecurity.token.TokenRepository;
import dev.bogdanjovanovic.accountsecurity.token.TokenUtils;
import dev.bogdanjovanovic.accountsecurity.user.UserRepository;
import java.util.ArrayList;
import java.util.List;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

  private final TokenUtils tokenUtils;
  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final TokenRepository tokenRepository;
  private final AuthenticationManager authenticationManager;

  public AuthService(final TokenUtils tokenUtils, final UserRepository userRepository,
      final PasswordEncoder passwordEncoder, final TokenRepository tokenRepository,
      final AuthenticationManager authenticationManager) {
    this.tokenUtils = tokenUtils;
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
        .requiresMfa(false)
        .build();
    userRepository.save(user);
  }

  @Transactional(isolation = Isolation.SERIALIZABLE)
  public AuthUser authenticate(final LoginRequest request) {
    final User user = userRepository.findByUsername(request.username())
        .orElseThrow(() -> new UnauthorizedException("Authentication failed"));
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            request.username(), request.password()
        ));
    if (user.requiresMfa()) {
      final String preAuthToken = tokenUtils.generateJwt(user, TokenType.PRE_AUTH);
      return new AuthUser(user.requiresMfa(), preAuthToken, null);
    }
    final String refreshToken = tokenUtils.generateJwt(user, TokenType.REFRESH);
    final String authToken = tokenUtils.generateJwt(user, TokenType.AUTH);
    revokeAllUserTokens(user);
    saveUserToken(user, refreshToken);
    return new AuthUser(user.requiresMfa(), authToken, refreshToken);
  }

  @Transactional(isolation = Isolation.READ_COMMITTED)
  public AuthUser refreshAuthToken(final String refreshToken) {
    final Token token = tokenRepository.findByToken(refreshToken)
        .orElseThrow(() -> new UnauthorizedException("Authentication failed"));
    final User user = token.getUser();
    final boolean isTokenValid = tokenUtils.isTokenValid(token.getToken(), user.getUsername(),
        TokenType.REFRESH, user.getRole());
    if (token.isRevoked() || !isTokenValid) {
      throw new UnauthorizedException("Authentication failed");
    }
    userRepository.findByUsername(user.getUsername())
        .orElseThrow(() -> new UnauthorizedException("Authentication failed"));
    final String authToken = tokenUtils.generateJwt(user, TokenType.AUTH);
    return new AuthUser(user.requiresMfa(), authToken, null);
  }

  private void revokeAllUserTokens(final User user) {
    final List<Token> validUserTokens = tokenRepository.findAllValidTokensByUserId(
        user.getUserId());
    if (validUserTokens.isEmpty()) {
      return;
    }
    validUserTokens.forEach(token -> token.setRevoked(true));
    tokenRepository.saveAll(validUserTokens);
  }

  private void saveUserToken(final User user, final String jwtToken) {
    final Token token = new Token(
        jwtToken,
        false,
        user
    );
    tokenRepository.save(token);
  }
}
