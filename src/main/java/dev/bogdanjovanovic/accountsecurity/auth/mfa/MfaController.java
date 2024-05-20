package dev.bogdanjovanovic.accountsecurity.auth.mfa;

import dev.bogdanjovanovic.accountsecurity.exception.ApiResponseWrapper;
import dev.samstevens.totp.exceptions.QrGenerationException;
import jakarta.validation.Valid;
import java.security.Principal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth/mfa")
//@CrossOrigin(origins = {"http://localhost:4200"})
@CrossOrigin
public class MfaController {

  private final static Logger log = LoggerFactory.getLogger(MfaController.class);
  private final MfaService mfaService;

  public MfaController(final MfaService mfaService) {
    this.mfaService = mfaService;
  }

  @PostMapping("setup")
  public ApiResponseWrapper<MfaSetupResponse> setupMfa(
      @RequestBody @Valid final MfaSetupRequest request, final Principal user)
      throws QrGenerationException {
    final String username = user.getName();
    log.info("Received a request to setup MFA for user '{}'", username);
    return new ApiResponseWrapper<>(mfaService.setupMfa(request, username));
  }

  @PostMapping("setup/confirm")
  public void confirmMfa(@RequestBody @Valid final MfaSetupConfirmRequest request,
      final Principal user) {
    final String username = user.getName();
    log.info("Received a request to confirm MFA for user '{}'", username);
    mfaService.confirmSetupMfa(request, username);
  }

//  @GetMapping
//  public String getSharedSecretQr() throws QrGenerationException {
//    final SecretGenerator secretGenerator = new DefaultSecretGenerator();
//    final String secret = secretGenerator.generate();
//    final QrData data = new QrData.Builder()
//        .label("johndoe@example.com")
//        .secret(secret)
//        .issuer("AccountSecurity")
//        .algorithm(HashingAlgorithm.SHA1)
//        .digits(6)
//        .period(60)
//        .build();
//    final QrGenerator generator = new ZxingPngQrGenerator();
//    final byte[] imageData = generator.generate(data);
//    final String mimeType = generator.getImageMimeType();
//    return getDataUriForImage(imageData, mimeType);
//  }

  @PostMapping("verify")
  public void verifyTotpCode(final Principal user) {
    final String username = user.getName();
    log.info("Received a request to verify TOTP code for user {}", username);
  }

}
