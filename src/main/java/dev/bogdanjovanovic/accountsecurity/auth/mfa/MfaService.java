package dev.bogdanjovanovic.accountsecurity.auth.mfa;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

import dev.bogdanjovanovic.accountsecurity.auth.mfa.totp.TotpDevice;
import dev.bogdanjovanovic.accountsecurity.auth.mfa.totp.TotpDeviceRepository;
import dev.bogdanjovanovic.accountsecurity.exception.BadRequestException;
import dev.bogdanjovanovic.accountsecurity.exception.ConflictException;
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
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class MfaService {

  private final UserRepository userRepository;
  private final TotpDeviceRepository totpDeviceRepository;

  public MfaService(final UserRepository userRepository,
      final TotpDeviceRepository totpDeviceRepository) {
    this.userRepository = userRepository;
    this.totpDeviceRepository = totpDeviceRepository;
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
}
