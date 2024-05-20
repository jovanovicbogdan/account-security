package dev.bogdanjovanovic.accountsecurity.totp;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;

public class TotpConverter implements AuthenticationConverter {

  private final Authentication authentication;

  public TotpConverter(final Authentication authentication) {
    this.authentication = authentication;
  }

  @Override
  public Totp convert(final HttpServletRequest request) {
    final String totpHeaderValue = request.getHeader(Totp.TOTP_HEADER_NAME);

    if (totpHeaderValue == null || totpHeaderValue.isBlank()) {
      return null;
    }

    return new Totp(authentication, totpHeaderValue);
  }
}
