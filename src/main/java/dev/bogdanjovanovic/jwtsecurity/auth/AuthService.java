package dev.bogdanjovanovic.jwtsecurity.auth;

import dev.bogdanjovanovic.jwtsecurity.auth.User.Role;
import dev.bogdanjovanovic.jwtsecurity.exception.ConflictException;
import dev.bogdanjovanovic.jwtsecurity.exception.UnauthorizedException;
import dev.bogdanjovanovic.jwtsecurity.token.Token;
import dev.bogdanjovanovic.jwtsecurity.token.Token.TokenType;
import dev.bogdanjovanovic.jwtsecurity.token.TokenRepository;
import dev.bogdanjovanovic.jwtsecurity.token.TokenService;
import jakarta.transaction.Transactional;
import java.util.List;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

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

  @Transactional
  public AuthResponse authenticate(final LoginRequest request) {
    final User user = userRepository.findByUsername(request.username())
        .orElseThrow(() -> new UnauthorizedException("Authentication failed"));
    authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
        request.username(), request.password()
    ));
//    if (!user.getUsername().equals(request.username()) || !passwordEncoder
//        .matches(request.password(), user.getPassword())) {
//      throw new UnauthorizedException("Authentication failed");
//    }
    revokeAllUserTokens(user);
    final String jwtToken = tokenService.generateJwtToken(user);
    saveUserToken(user, jwtToken);
    return new AuthResponse(jwtToken);
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
        TokenType.BEARER,
        false,
        false,
        user
    );
    tokenRepository.save(token);
  }
}
