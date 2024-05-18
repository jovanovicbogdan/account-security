package dev.bogdanjovanovic.jwtsecurity.auth.mfa.totp;

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
    final String otpHeaderValue = request.getHeader("otp");

    if (otpHeaderValue == null || otpHeaderValue.isBlank()) {
      return null;
    }

    return new Totp(authentication, otpHeaderValue);
  }
}
