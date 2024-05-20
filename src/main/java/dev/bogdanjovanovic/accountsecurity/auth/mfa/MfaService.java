package dev.bogdanjovanovic.accountsecurity.auth.mfa;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

import dev.bogdanjovanovic.accountsecurity.auth.AuthUser;
import dev.bogdanjovanovic.accountsecurity.exception.BadRequestException;
import dev.bogdanjovanovic.accountsecurity.exception.ConflictException;
import dev.bogdanjovanovic.accountsecurity.exception.UnauthorizedException;
import dev.bogdanjovanovic.accountsecurity.token.Token;
import dev.bogdanjovanovic.accountsecurity.token.Token.TokenType;
import dev.bogdanjovanovic.accountsecurity.token.TokenRepository;
import dev.bogdanjovanovic.accountsecurity.token.TokenUtils;
import dev.bogdanjovanovic.accountsecurity.totp.TotpDevice;
import dev.bogdanjovanovic.accountsecurity.totp.TotpDeviceRepository;
import dev.bogdanjovanovic.accountsecurity.user.User;
import dev.bogdanjovanovic.accountsecurity.user.UserRepository;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class MfaService {

  private final UserRepository userRepository;
  private final TotpDeviceRepository totpDeviceRepository;
  private final TokenRepository tokenRepository;
  private final TokenUtils tokenUtils;

  public MfaService(final UserRepository userRepository,
      final TotpDeviceRepository totpDeviceRepository, final TokenRepository tokenRepository,
      final TokenUtils tokenUtils) {
    this.userRepository = userRepository;
    this.totpDeviceRepository = totpDeviceRepository;
    this.tokenRepository = tokenRepository;
    this.tokenUtils = tokenUtils;
  }

  @Transactional(isolation = Isolation.READ_COMMITTED)
  public MfaSetupResponse setupMfa(final MfaSetupRequest request, final String username)
      throws QrGenerationException {
    final User user = userRepository.findByUsername(username)
        .orElseThrow(() -> new BadRequestException("User not found"));
    final SecretGenerator secretGenerator = new DefaultSecretGenerator();
    final String secret = secretGenerator.generate();
    final String deviceName = request.deviceName();
    totpDeviceRepository.findByDeviceName(deviceName)
        .ifPresent((device) -> {
          throw new ConflictException(
              String.format("Device with name '%s' already exists.", device.getDeviceName()));
        });
    final TotpDevice totpDevice = new TotpDevice(deviceName, secret, false, false, user);
    totpDeviceRepository.save(totpDevice);
    return new MfaSetupResponse(generateQrImage(user.getEmail(), secret), secret);
  }

  @Transactional(isolation = Isolation.READ_COMMITTED)
  public void confirmSetupMfa(final MfaSetupConfirmRequest request, final String username) {
    final User user = userRepository.findByUsername(username)
        .orElseThrow(() -> new BadRequestException("User not found"));
    final TotpDevice totpDevice = totpDeviceRepository.findByUser(user)
        .orElseThrow(() -> new BadRequestException("Need to setup MFA first"));
    if (totpDevice.isConfirmed()) {
      throw new ConflictException("MFA already confirmed");
    }
    final TimeProvider timeProvider = new SystemTimeProvider();
    final CodeGenerator codeGenerator = new DefaultCodeGenerator();
    final CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
    boolean isSuccessful = verifier.isValidCode(totpDevice.getSecret(), request.code());
    if (!isSuccessful) {
      throw new BadRequestException("MFA confirmation failed");
    }
    totpDevice.setConfirmed(true);
    totpDevice.setEnabled(true);
    totpDeviceRepository.save(totpDevice);
  }

  @Transactional(isolation = Isolation.SERIALIZABLE)
  public MfaAuthUser verifyTotpCode(final String code, final String username) {
    final User user = userRepository.findByUsername(username)
        .orElseThrow(() -> new UnauthorizedException("Authentication failed"));
    final boolean isSuccessful = isSuccessful(user, code);
    if (!isSuccessful || !user.requiresMfa()) {
      throw new UnauthorizedException("Authentication failed");
    }
    final String refreshToken = tokenUtils.generateJwt(user, TokenType.REFRESH);
    final String authToken = tokenUtils.generateJwt(user, TokenType.AUTH);
    final List<Token> validUserTokens = tokenRepository.findAllValidTokensByUserId(
        user.getUserId());
    if (!validUserTokens.isEmpty()) {
      validUserTokens.forEach(token -> token.setRevoked(true));
      tokenRepository.saveAll(validUserTokens);
    }
    final Token token = new Token(refreshToken, false, user);
    tokenRepository.save(token);
    return new MfaAuthUser(authToken, refreshToken);
  }

  private String generateQrImage(final String label, final String secret)
      throws QrGenerationException {
    final QrData data = new QrData.Builder()
        .label(label)
        .secret(secret)
        .issuer("Account Security")
        .algorithm(HashingAlgorithm.SHA1)
        .digits(6)
        .period(60)
        .build();
    final QrGenerator generator = new ZxingPngQrGenerator();
    final byte[] imageData = generator.generate(data);
    final String mimeType = generator.getImageMimeType();
    return getDataUriForImage(imageData, mimeType);
  }

  private boolean isSuccessful(final User user, final String code) {
    final TotpDevice totpDevice = user.getTotpDevice();
    if (totpDevice == null) {
      throw new UnauthorizedException("Authentication failed");
    }
    if (!totpDevice.isConfirmed() || !totpDevice.isEnabled()) {
      throw new UnauthorizedException("Authentication failed");
    }
    final TimeProvider timeProvider = new SystemTimeProvider();
    final CodeGenerator codeGenerator = new DefaultCodeGenerator();
    final CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
    return verifier.isValidCode(totpDevice.getSecret(), code);
  }
}
