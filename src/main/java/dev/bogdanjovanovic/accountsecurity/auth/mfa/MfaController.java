package dev.bogdanjovanovic.accountsecurity.auth.mfa;

import dev.bogdanjovanovic.accountsecurity.auth.AuthController;
import dev.bogdanjovanovic.accountsecurity.exception.ApiResponseWrapper;
import dev.samstevens.totp.exceptions.QrGenerationException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import java.security.Principal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth/mfa")
@CrossOrigin(origins = {"http://localhost:4200"}, allowCredentials = "true")
public class MfaController {

  private final static Logger log = LoggerFactory.getLogger(MfaController.class);

  @Value("${security.refresh-token-expiration}")
  private long refreshTokenExpiration;
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

  @PostMapping("verify")
  public ApiResponseWrapper<MfaVerificationResponse> verifyTotpCode(
      final HttpServletRequest request, final HttpServletResponse response,
      final Principal user) {
    final String code = request.getHeader("totp");
    if (code == null || code.isBlank()) {
      response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      response.setHeader("WWW-Authenticate", "TOTP");
      return new ApiResponseWrapper<>(null);
    }
    final String username = user.getName();
    log.info("Received a request to verify TOTP code for user '{}'", username);
    final MfaAuthUser mfaAuthUser = mfaService.verifyTotpCode(code, username);
    final Cookie cookie = new Cookie(AuthController.REFRESH_TOKEN_COOKIE_NAME,
        mfaAuthUser.refreshToken());
    cookie.setHttpOnly(true);
    cookie.setPath("/");
    cookie.setMaxAge((int) (refreshTokenExpiration / 1000));
    cookie.setAttribute("SameSite", "Strict");
//    cookie.setSecure(true);
    response.addCookie(cookie);
    return new ApiResponseWrapper<>(new MfaVerificationResponse(mfaAuthUser.authToken()));
  }

}
