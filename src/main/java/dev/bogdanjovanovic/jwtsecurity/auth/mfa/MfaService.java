package dev.bogdanjovanovic.jwtsecurity.auth.mfa;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

import dev.bogdanjovanovic.jwtsecurity.auth.mfa.totp.TotpDevice;
import dev.bogdanjovanovic.jwtsecurity.auth.mfa.totp.TotpDeviceRepository;
import dev.bogdanjovanovic.jwtsecurity.exception.ConflictException;
import dev.bogdanjovanovic.jwtsecurity.exception.UnauthorizedException;
import dev.bogdanjovanovic.jwtsecurity.user.User;
import dev.bogdanjovanovic.jwtsecurity.user.UserRepository;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
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
        .orElseThrow(() -> new UnauthorizedException("Authentication failed"));
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
    final QrData data = new QrData.Builder()
        .label(user.getEmail())
        .secret(secret)
        .issuer("Account Security")
        .algorithm(HashingAlgorithm.SHA1)
        .digits(6)
        .period(60)
        .build();
    final QrGenerator generator = new ZxingPngQrGenerator();
    final byte[] imageData = generator.generate(data);
    final String mimeType = generator.getImageMimeType();
    return new MfaSetupResponse(getDataUriForImage(imageData, mimeType), secret);
  }
}
