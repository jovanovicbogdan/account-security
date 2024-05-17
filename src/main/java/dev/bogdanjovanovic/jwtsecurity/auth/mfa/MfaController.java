package dev.bogdanjovanovic.jwtsecurity.auth.mfa;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth/mfa")
//@CrossOrigin(origins = {"http://localhost:4200"}, allowCredentials = "true")
@CrossOrigin
public class MfaController {

  private final static Logger log = LoggerFactory.getLogger(MfaController.class);

  @GetMapping
  public String getSharedSecret() throws QrGenerationException {
    final SecretGenerator secretGenerator = new DefaultSecretGenerator();
    final String secret = secretGenerator.generate();
    final QrData data = new QrData.Builder()
        .label("johndoe@example.com")
        .secret(secret)
        .issuer("AccountSecurity")
        .algorithm(HashingAlgorithm.SHA1)
        .digits(6)
        .period(60)
        .build();
    final QrGenerator generator = new ZxingPngQrGenerator();
    final byte[] imageData = generator.generate(data);
    final String mimeType = generator.getImageMimeType();
    return getDataUriForImage(imageData, mimeType);
  }

  @PostMapping
  public void verifyOtpCode() {
    log.info("Verifying OTP code...");
  }

}
