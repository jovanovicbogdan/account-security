package dev.bogdanjovanovic.jwtsecurity.auth.mfa;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

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

@Service
public class MfaService {

  private final UserRepository userRepository;

  public MfaService(final UserRepository userRepository) {
    this.userRepository = userRepository;
  }

  public MfaSetupResponse setupMfa(final String username) throws QrGenerationException {
    final User user = userRepository.findByUsername(username)
        .orElseThrow(() -> new UnauthorizedException("Authentication failed"));
    final SecretGenerator secretGenerator = new DefaultSecretGenerator();
    final String secret = secretGenerator.generate();
    final QrData data = new QrData.Builder()
        .label(user.getEmail())
        .secret(secret)
        .issuer("AccountSecurity")
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
